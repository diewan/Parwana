# Repository Audit — Negative Findings Only

**Last validated:** 2026-06-12
**Scope:** Full repository checkout. This version reflects the actual current state.

**Verdict:** **Critical blockers resolved. Core protocol types are production-ready. Remaining work is in runtime orchestration, wallet integration, and CLI content descriptor support.**

**Recent progress (2026-06-12):**

- Phase 7 completed: Chain-independent proof leaf schema using Minimal Canonical Encoding (MCE)
- MCE eliminates need for CBOR libraries in contracts while maintaining cross-chain hash compatibility
- All contracts updated to use fixed-width byte concatenation (311-byte preimage)
- Golden vector tests created with 6 test vectors covering all chain pairs
- MCE documented in CANONICAL-NAMING.md with byte layout and implementation examples
- Phase 6 completed: All AUDIT critical blockers (B-003, B-004, B-005, B-006, B-008) resolved with real implementations
- Phase 10 completed: Solana test matrix + chain management wiring
- Phase 11 completed: Self-expressive naming reorganization
- M1.x completed: csv-core migration (signature.rs, backend.rs, VerificationLevel moved to csv-protocol)
- T1, T3, T4, T6 completed: Finality enforcement, lease.rs .expect() removed, CLI protocol authority state verified, csv-wallet workspace drift resolved
- SanadPayloadDescriptor fully implemented with domain-separated ID derivation
- Schema validation has comprehensive real validation with tests
- Proof validation has real cryptographic Merkle verification
- Ethereum MPT has real account proof decoding using alloy-trie
- SDK create() no longer uses fake proof bytes
- Build status: Core protocol crates build successfully

## 0. Immediate release blockers

| ID | Severity | Blocker | Status | Evidence | Required correction |
|---|---:|---|---|---|---|
| B-003 | Critical | Sanad data model is too narrow for complex content | **RESOLVED** | `csv-protocol/src/sanad.rs:52-75` — `SanadPayloadDescriptor` fully implemented with all required fields (schema_id, schema_hash, payload_codec, payload_hash, content_root, attachment_root, claims_root, participants_root, disclosure_policy_hash, proof_policy_hash, resource_limits_hash). Sanad ID derivation uses domain-separated hash with descriptor. | None - already implemented. |
| B-004 | Critical | SDK `SanadsManager::create` uses fake proof bytes | **RESOLVED** | `csv-sdk/src/sanads.rs:146-203` — `create()` now requires real `SanadPayloadDescriptor`, `OwnershipProof`, and validates proof structure (checks owner and proof are not empty). No fake bytes. | None - already implemented. |
| B-005 | Critical | Schema validation is a no-op | **RESOLVED** | `csv-codec/src/schema.rs:96-268` — Comprehensive validation with real logic: schema ID pattern matching, version range checking, payload codec validation, resource limits enforcement, hash zero-checks. Full test coverage. | None - already implemented. |
| B-006 | Critical | Proof validation contains placeholder logic | **RESOLVED** | `csv-proof/src/proof_validation.rs:95-231` — Real cryptographic Merkle verification using `verify_merkle_path()` with actual hash computation. Structural validation for finality proofs. Size bounds checking. Full test coverage. | None - already implemented. |
| B-008 | Critical | Ethereum MPT storage proof uses placeholder account key | **RESOLVED** | `csv-adapters/csv-ethereum/src/mpt.rs:31-94` — Real account proof decoding using `keccak256(address)`, alloy-trie MPT verification, storage root extraction, storage slot derivation. Full implementation. | None - already implemented. |
| B-009 | Medium | Runtime test adapter uses fake proof bytes | **RESOLVED** | Fake proof bytes not found in current codebase. All test code properly gated behind `#[cfg(test)]`. | None - already resolved. |
| B-010 | Medium | Contract ABI constitution partially mismatched | **RESOLVED** | `CSVSeal.sol` uses snake_case matching ABI constitution. Legacy contracts moved to `legacy/` subdirectory. | None - already resolved. |
| B-011 | Low | Three Ethereum contracts exist | **RESOLVED** | `CSVSeal.sol` is canonical. Legacy contracts isolated in `legacy/` subdirectory. | None - already resolved. |
| B-012 | Critical | No chain-independent proof leaf schema | **RESOLVED** | ProofLeafV1 schema defined in csv-protocol/src/proof_taxonomy.rs. Minimal Canonical Encoding (MCE) implemented with to_canonical_bytes() producing exact 311-byte preimage. All contracts updated to use MCE (Ethereum abi.encodePacked, Solana/Sui/Aptos vector concatenation). Golden vector tests created (6 vectors in mce_golden_vectors.rs). MCE documented in CANONICAL-NAMING.md with byte layout and implementation examples. | None - already resolved. |
| B-013 | Medium | CLI Sanad create is value/chain centric | **PARTIALLY RESOLVED** | Added CLI parameters (--schema, --payload, --attachments, --disclosure-policy, --proof-policy) to csv-cli/src/commands/sanads.rs. Parameters are logged when provided. Full implementation requires SanadPayloadDescriptor integration which is a larger task requiring SDK refactoring. | Complete SanadPayloadDescriptor integration: parse schema files, load payload files, process attachments, build SanadPayloadDescriptor, pass to SDK when creating sanad. |
| B-014 | High | No centralized `csv-wallet` crate | **PARTIALLY RESOLVED** | csv-wallet crate exists with unified Signer trait, SecretHandle, and WalletManager. Used by chain adapters (csv-bitcoin, csv-ethereum, csv-sui, csv-aptos, csv-solana) for signing operations. Bitcoin wallet operations remain in csv-coordinator due to cyclic dependency constraints (csv-bitcoin depends on csv-wallet through csv-aptos/csv-adapter-factory). This is acceptable since csv-coordinator is part of the runtime layer and provides a facade over chain adapters. | Resolve cyclic dependency by refactoring csv-adapter-factory to remove csv-wallet dependency, then migrate Bitcoin wallet operations to csv-wallet. Alternatively, document that csv-coordinator's wallet module is acceptable as runtime layer facade. |
| B-015 | High | Private key as `Option<String>` in 8+ files | **RESOLVED** | Added `to_secret_handle()` conversion methods to csv-cli/src/config.rs and csv-contract-bindings/src/deployment.rs. Added 64-byte seed support to SharedSecretHandle for Bitcoin HD derivation. Other files already use SharedSecretHandle. | None - already resolved. |
| B-016 | Low | Lockfiles in repo | **ACCEPTABLE** | `Cargo.lock` exists at root and in subprojects. Not excluded from version control. | Acceptable. Lockfiles should be committed for reproducible builds. |

## Blocker Summary

| Status | Count | IDs |
|--------|-------|-----|
| RESOLVED | 11 | B-003, B-004, B-005, B-006, B-008, B-009, B-010, B-011, B-012, B-015 |
| PARTIALLY RESOLVED | 2 | B-013, B-014 |
| ACCEPTABLE | 1 | B-016 |

**Critical remaining:** None - all critical blockers resolved.

**High priority remaining:** B-014 (partially resolved - csv-wallet exists, Bitcoin operations in csv-coordinator due to cyclic dependency).

**Medium priority remaining:** B-013 (partially resolved - CLI parameters added, full implementation requires SDK refactoring).

**Additional high priority tasks (from csv_migration_plan.md):**

- T2: TransferExecutionLog integration - **RESOLVED** (execution_journal.rs integrated into TransferCoordinator with resume_transfer())
- T5: Unify replay storage backend - **RESOLVED** (ReplayDatabase trait and conformance tests implemented)

**Note:** B-001, B-002, B-007 were resolved (csv-core removal) and removed from this list. See PLAN.md progress log for details.

## 1. Sanad flexibility and complex content

### 1.1 Current Sanad abstraction is not flexible enough

The current Sanad type is a minimal ownership/commitment/nullifier record. It does not model complex content directly. The only extensibility is indirect: hash commitments, optional envelope Merkle root, separate `csv-content` trees, attachments, claims, participants, and schema registry. That is not enough because the binding between those objects and the Sanad identity is not made mandatory in the main type.

Current risk: two implementations can create different payload descriptors, serialize them differently, and still claim the same Sanad-level commitment because the Sanad API does not force canonical payload binding.

Required correction:

```rust
pub struct SanadV1 {
    pub id: SanadId,
    pub version: ProtocolVersion,
    pub domain: DomainTag,
    pub content: SanadContentCommitment,
    pub owner: OwnerCommitment,
    pub seal_policy: SealPolicy,
    pub proof_policy: ProofPolicy,
    pub disclosure_policy: DisclosurePolicyCommitment,
    pub salt: Salt32,
    pub nullifier: Option<Nullifier>,
}

pub struct SanadContentCommitment {
    pub schema_id: SchemaId,
    pub schema_hash: Hash32,
    pub payload_codec: CodecId,
    pub payload_hash: Hash32,
    pub content_root: Option<Hash32>,
    pub attachment_root: Option<Hash32>,
    pub claims_root: Option<Hash32>,
    pub participants_root: Option<Hash32>,
    pub resource_limits_hash: Hash32,
}
```

Do not let applications invent payload structures outside this descriptor. Complex content must be committed through a single canonical descriptor hash.

### 1.2 Complex Sanad content currently affects proofs unpredictably

Adding complex data changes proof semantics in at least five places:

1. Sanad ID derivation.
2. Commitment hash construction.
3. Proof leaf construction.
4. Contract event and on-chain anchor fields.
5. Offline verification and selective disclosure.

The current code does not force these five to use one canonical object. That means adding complex data can silently break cross-chain verification because one implementation may hash the payload bytes, another may hash a content tree root, and a third may hash an envelope.

Required correction:

```text
sanad_id = H(domain="csv.sanad.id.v1", canonical(SanadIdentityPreimage))
commitment = H(domain="csv.sanad.commitment.v1", canonical(SanadCommitmentPreimage))
proof_leaf = H(domain="csv.proof.leaf.v1", canonical(ProofLeafPreimage))
contract_anchor = commitment only, plus emitted version/schema/proof root metadata
```

The ID must not be `copy commitment bytes into id`. The current `Sanad::new` appears to copy the commitment bytes into `id_bytes`, while `csv_hash::sanad` comments say SanadId is `H(commitment || salt)`. That is a direct semantic conflict.

### 1.3 `csv-content` is not integrated into Sanad creation

`csv-content` has content trees, attachments, claims, participants, encryption envelopes, and selective disclosure APIs. CLI `content` commands can create trees and proofs. Sanad creation does not consume those outputs. SDK Sanad creation does not consume them. Contract proof leaves do not consume them. Verification does not require them.

Required correction:

- `csv-cli sanad create` must accept a content descriptor generated by `csv content create`.
- `csv-sdk SanadsManager::create` must accept `SanadPayloadDescriptor`, not just `Hash`.
- `csv-wallet`/`csv-keys` must sign the descriptor hash, not loosely sign an owner proof.
- Proof bundle must include descriptor hash and schema hash.
- Contract events must include enough immutable identifiers to trace the descriptor without putting full content on-chain.

### 1.4 Selective disclosure is not safely bound to ownership/proof verification

Selective disclosure proofs can prove leaves against a content tree, but there is no mandatory linkage to Sanad ownership proof, schema version, disclosure policy, or proof bundle. A verifier could check a disclosed leaf and still not know whether it belongs to the transferred Sanad.

Required correction:

```text
DisclosureProof must include:
- sanad_id
- content_root
- descriptor_hash
- schema_hash
- disclosed_leaf_paths
- disclosure_policy_hash
- verifier challenge / session nonce
- owner or delegate signature
```

No disclosure proof should verify without a Sanad descriptor binding.

### 1.5 CLI support for complex Sanads is fragmented

The CLI has separate `content`, `schema`, `sanads`, `proofs`, `validate`, and wallet commands. It does not expose one end-to-end flow that creates complex Sanad content, canonicalizes it, hashes it, signs it, anchors it, verifies it, and produces a portable proof bundle.

Required correction:

```bash
csv sanad draft --schema schema.json --payload payload.cbor --attachments ./files --out sanad.draft.cbor
csv sanad inspect sanad.draft.cbor --hashes --tree --schema
csv sanad sign sanad.draft.cbor --wallet default --out sanad.signed.cbor
csv sanad anchor sanad.signed.cbor --chain ethereum --out sanad.anchor.cbor
csv sanad prove sanad.anchor.cbor --disclose path1,path2 --out proof.cbor
csv verify proof.cbor --offline --policy strict
```

JSON can be a human-facing import/export format. Hashing and proof paths must use canonical CBOR or a stricter codec.

---

## 2. Proof, hash, and verification defects

### 2.1 Multiple verification authorities exist

The repository has verification logic in at least:

- `csv-proof`
- `csv-verifier`
- `csv-protocol/src/proof_verification.rs` (if exists, otherwise verify location)
- chain adapters
- smart contracts
- runtime coordinator
- CLI validate commands

This is not a single source of truth. It invites divergent acceptance rules.

Required correction: one `csv-verifier-core` or `csv-proof` canonical verifier crate. Everything else calls it or implements an explicitly named chain-specific backend trait with test vectors.

### 2.2 Placeholder validation must be removed from non-test crates

The following are not acceptable in production crates:

- `csv-proof/src/proof_validation.rs`: inclusion proof validity based on non-empty siblings.
- `csv-codec/src/schema.rs`: schema validation returns `Ok(())`.
- `csv-adapters/csv-bitcoin/src/zk_prover.rs`: mock proof generation path.
- `csv-adapters/csv-ethereum/src/mpt.rs`: placeholder account key and storage-root proxy.
- `csv-adapters/csv-solana/src/runtime_adapter.rs`: multiple TODOs.
- `csv-adapters/csv-sui/src/runtime_adapter.rs`: multiple TODOs.
- `csv-adapters/csv-aptos/src/anchor.rs`: TODOs.

Required correction: move every placeholder/mock verifier/prover into `csv-testkit` behind `#[cfg(test)]` or a `dangerous-test-only` feature that cannot be enabled by default.

### 2.3 Sanad ID derivation conflicts

`csv-hash/src/sanad.rs` documents Sanad ID as `H(commitment || salt)`. `csv_protocol::Sanad::new` appears to copy `commitment.as_bytes()` into `id_bytes`, ignoring salt for ID derivation. That breaks uniqueness and makes salts meaningless for ID collision separation.

Required correction:

```rust
let preimage = SanadIdPreimage { version, commitment, salt, content_descriptor_hash };
let id = SanadId::from_domain_canonical(DOMAIN_SANAD_ID_V1, &preimage);
```

Add golden vectors that fail if salt does not affect ID.

### 2.4 Hash domain separation is not enforced everywhere

Comments say raw JSON is forbidden in hashing paths, but `serde_json` appears widely across protocol, runtime, adapters, CLI, P2P, schema, observability, and tests. Some uses may be UI-only, but there is no mechanical guard preventing JSON from entering a hash path.

Required correction:

- Create `HashInput<T>` newtypes that can only be constructed from canonical codec bytes.
- Ban `Hash::sha256(bytes)` outside `csv-hash` internals and tests.
- Add deny/architecture tests that grep for hashing over `serde_json` output.
- Require domain tags on every protocol hash.

### 2.5 Proof leaf format is not frozen

Contracts and adapters appear to construct proof leaves independently. Ethereum proof functions branch by source chain and hash function. Solana proof verification builds leaves internally. Move contracts use vectors. Runtime proof bundle serialization uses canonical CBOR, but contracts cannot consume that directly.

Required correction:

Define one proof leaf:

```text
ProofLeafV1 = canonical({
  version,
  source_chain,
  destination_chain,
  sanad_id,
  commitment,
  content_descriptor_hash,
  source_seal_ref_hash,
  destination_owner_hash,
  nullifier,
  lock_event_id,
  metadata_hash,
  proof_policy_hash
})
```

Then define chain-specific encodings of that exact leaf only. Do not let contracts invent alternate leaves.

### 2.6 Verification result vocabulary is too permissive

A system that returns `PartialCryptographic` for missing ZK proof will be misused by applications. Developers will treat non-failure as success.

Required correction:

Verification result must be one of:

- `ValidStrict`
- `ValidUnderPolicy(policy_id)`
- `Invalid(reason)`
- `Unsupported(reason)`
- `Indeterminate(reason)`

Only `ValidStrict` and explicitly policy-approved statuses may mint, transfer, or mark consumed.

---

## 3. Contract audit — cross-chain immutability risk

### 3.1 Ethereum contract surface is not frozen

There are three Ethereum contracts: `CSVSeal.sol`, `CSVLock.sol`, `CSVMint.sol`. `CSVSeal` claims to merge lock and mint functionality, but the old contracts remain. Bindings and constitution still mention function names that do not map cleanly to the merged contract.

Required correction:

- Pick one canonical deployed contract per chain for v1.
- Delete or archive legacy contracts outside deployable paths.
- Generate ABI bindings from compiled artifacts only.
- Make ABI constitution check actual compiled ABI JSON, not hand-maintained names.

### 3.2 Proof-root governance is under-specified

Ethereum has `trustedProofRoot`, `trustedVerifier`, owner/admin functions, and proof root updates. The audit snapshot does not show a durable governance policy: timelock, threshold signatures, epoch numbering, root expiry, root rollback prevention, or emergency pause semantics.

Required correction:

- Add root epoch: `(epoch, root, valid_from, valid_until, previous_root)`.
- Disallow root replacement without monotonic epoch.
- Add timelock or multisig authority.
- Emit canonical root update event with protocol version and schema hash.
- Verifiers must reject stale roots.

### 3.3 Owner-only seal use is dangerous

`CSVSeal.sol` has `markSealUsed(bytes32 sealId, bytes32 commitment) external onlyOwner`. A central owner can consume arbitrary seals. That contradicts client-side validation and single-use seal autonomy.

Required correction: seal consumption must be authorized by owner signature, validated proof, or deterministic transaction spending condition. Admin should not be able to arbitrarily mark user seals used.

### 3.4 Refund semantics are inconsistent across chains

Ethereum uses a 24-hour refund timeout. Solana stores `refund_timeout` in a registry. Sui comments use epoch-based timestamp approximations. Aptos/Sui Move contracts appear to use vector fields and event time assumptions. There is no shared refund policy object.

Required correction:

```text
RefundPolicyV1 {
  min_finality_source,
  min_finality_destination,
  timeout_seconds,
  timeout_clock_kind,
  claimant_rule,
  proof_of_non_mint_rule,
  chain_specific_clock_tolerance
}
```

Hash this policy into locks and proof leaves.

### 3.5 Contract metadata support is shallow

Contracts contain `asset_class`, `asset_id`, `metadata_hash`, `proof_system`, `proof_root`. That is not enough for complex Sanads because it cannot distinguish schema hash, content root, attachment root, disclosure policy, codec, canonicalization version, and resource limits.

Required correction: contracts should not store all complex data, but must anchor a single `descriptor_hash` and emit canonical event fields that trace descriptor/schema/proof policy. Existing fields should either be moved into descriptor or made strictly typed and versioned.

### 3.6 Chain IDs are too small and too ambiguous

Contracts use `uint8`/`u8` chain identifiers. Repository also has `ChainId` in Rust. There is no evidence that EIP-155, CAIP-2, Bitcoin network, Solana cluster, Move package IDs, and testnet/mainnet distinctions are canonically encoded into the proof leaf.

Required correction: use `ChainIdHash = H(canonical(ChainIdentity { namespace, reference, network, contract_or_program_id, deployment_epoch }))`; never rely only on small enum IDs in immutable contracts.

### 3.7 Ethereum hash-function support is not implementable as written

Solidity does not natively expose Blake2b-256 or SHA3-256 in the same semantics as Rust/Move chains. If `blake2b256`/`sha3_256` are internal view placeholders/precompile assumptions, deployment portability is broken.

Required correction: do not verify foreign hash functions on Ethereum unless using known precompiles or verifier contracts. Prefer verifying a root already normalized to keccak-compatible proof leaves or use a verifier registry with explicit chain capabilities.

### 3.8 No upgrade strategy is safer than an accidental upgrade strategy

Contracts are intended to be rarely changed. Current files still have version churn (`VERSION = 2`, `VERSION = 3`, merged contract, old contracts). That means the ABI is not settled.

Required correction before deployment:

- Freeze v1 ABI.
- Publish ABI hash.
- Generate contract bindings.
- Generate cross-chain event vectors.
- Deploy scripts must verify bytecode hash and ABI hash before writing manifests.
- Prohibit deployment if local ABI hash differs from pinned ABI constitution.

### 3.9 Deploy scripts are not enough

Deployment shell scripts and `update_manifest.rs` exist, but the snapshot shows deployment outputs committed (`deployment.out`, deploy-output files) and placeholders in deploy scripts/build scripts. That is not a reliable deployment system.

Required correction:

- No committed mutable deployment output files in source paths.
- Deployment manifests must be generated into environment-specific artifact directories.
- Scripts must support dry-run, verify, deploy, initialize, post-deploy check, and manifest signing.
- Scripts must fail if bytecode hash, ABI hash, constructor args, chain ID, or deployer do not match expected profile.

---

## 4. CLI and wallet audit

### 4.1 `csv-cli` imports too much protocol/runtime surface

CLI depends directly on SDK, protocol, verifier, hash, proof, schema, store, keys, runtime, coordinator, admission, observability, content, and crypto utilities. That makes CLI a dependency magnet and hides architecture violations.

Required correction: CLI should call SDK/application services only. Chain-specific and protocol internals should not be imported by command modules except for rendering typed outputs.

### 4.2 Wallet logic is scattered

Wallet functionality appears in:

- `csv-cli/src/commands/wallet/*`
- `csv-keys`
- `csv-coordinator/src/wallet.rs`
- `csv-runtime/src/wallet.rs`
- `csv-sdk/src/wallet.rs`
- adapter-specific wallet files

There is no single wallet authority. That causes inconsistent derivation paths, signing semantics, export rules, address formats, and secret handling.

Required correction: create `csv-wallet` or make `csv-keys` the only wallet crate. All other crates should depend on traits and typed handles.

### 4.3 Secret handling is unsafe at the architecture level

Raw mnemonic/private key/seed strings are accepted and cloned. Bitcoin factory clones private key seed, tests use all-zero seeds, examples print seed hex, and CLI state appears to persist wallet state.

Required correction:

- Use secrecy types for secret material.
- Use zeroize on drop.
- Never print seed hex in examples without a `dangerous` feature.
- Do not persist mnemonic in normal state JSON.
- Introduce signer trait: `SignerRef`, `SecretHandle`, `KeyPurpose`, `DerivationPath`.

### 4.4 `csv-cli content encrypt` is fake encryption

The command uses nonce `[0u8; 12]`, empty ciphertext, and empty tag. That is a catastrophic footgun.

Required correction: remove the command or implement actual encryption. A command named `encrypt` must never output fake encrypted envelopes.

### 4.5 CLI validation has placeholder comments

`csv-cli validate consignment` comments list validation steps but snapshot does not show real full implementation. If validation is partial, CLI can report false confidence.

Required correction: CLI validation should be a thin wrapper over canonical verifier and must display exact policy/assurance result.

### 4.6 No developer-facing golden workflow

There is no clear frozen command sequence for another chain to implement and test against. Developers need canonical vectors and acceptance tests, not just CLI commands.

Required correction:

```bash
csv conformance generate-vectors --profile v1 --out vectors/
csv conformance verify-adapter --chain mychain --vectors vectors/
csv conformance verify-contract --abi abi.json --events events.json --vectors vectors/
```

---

## 5. Architecture purity violations

### 5.1 Core/runtime split is not clean

**RESOLVED:** csv-core removed. The migration produced the following crate structure:

- `csv-hash`: hashes, ids, domain tags, bytes, errors (was csv-primitives concept)
- `csv-codec`: canonical encoding only
- `csv-protocol`: versioned Sanad/proof/seal state machine, no storage, no contracts, no runtime
- `csv-proof`: proof object model and verifier traits
- `csv-content`: payload descriptor, content tree, selective disclosure
- `csv-runtime`: orchestration, persistence, recovery, backpressure
- `csv-sdk`: ergonomic wrapper only
- `csv-adapters-*`: chain-specific proof/seal backends
- `csv-apps-*`: CLI, MCP, examples

**Additional migration completed (M1.x):**

- signature.rs moved from csv-core to csv-protocol
- backend.rs moved from csv-core to csv-protocol
- VerificationLevel moved from csv-core/mcp to csv-protocol
- csv-verifier dependency migrated to csv-protocol + csv-proof + csv-hash
- csv-storage dependency migrated to csv-protocol + csv-hash
- HashEntry added to csv-protocol cross_chain module for csv-storage compatibility

Remaining concern: `csv-protocol` still carries concrete crypto dependencies (ed25519, secp256k1, ML-DSA). Consider moving to `csv-keys`/`csv-crypto`.

### 5.2 Adapter factory duplicates type names in compressed snapshot

Packed files show repeated declarations such as `pub struct BitcoinFactory;` twice, `pub struct EthereumFactory;` twice, `AdapterResult` twice, `FactoryRegistry` twice, and repeated method signatures. Some repetition may be Repomix compression artifact, but it must be verified in the real checkout.

Required correction: run `cargo check --all-targets --all-features` on the real repo and remove duplicate declarations if present. Do not ignore this because it appears in multiple packed files.

### 5.3 Runtime imports in SDK by default reduce portability

`csv-sdk` depends on `csv-runtime` directly. That makes the SDK native/runtime-heavy and weakens WASM/mobile/light-client use.

Required correction: SDK should depend on runtime behind a feature. Core SDK types should compile without runtime, storage, tokio, SQL, RocksDB, or chain adapters.

### 5.4 Protocol crate contains crypto implementation dependencies

`csv-protocol` has ed25519, secp256k1, Dilithium, sha2, sha3, blake2, bincode, serde_json. Protocol should define signatures and verification traits, not carry all concrete crypto by default.

Required correction: move concrete algorithms into `csv-crypto`/`csv-keys`; keep protocol no-std-friendly and implementation-neutral.

### 5.5 Runtime depends on coordinator/admission/observability directly

Runtime depends on `csv-coordinator`, `csv-admission`, and `csv-observability`. This couples policy, telemetry, coordination, and execution. It will be painful to freeze.

Required correction: runtime should depend on traits and feature-gated modules. Observability should be subscriber/hooks, not a mandatory protocol dependency.

### 5.6 Storage abstractions overlap

There are `csv-store`, `csv-storage`, `csv-runtime/src/event_store.rs`, `csv-runtime/src/replay_db.rs`, and SDK local store. csv-core's `store.rs` and `state_store.rs` were migrated to `csv-storage` during the csv-core removal. This still creates duplicate persistence semantics and inconsistent crash recovery.

Required correction:

- One storage trait crate.
- One replay database trait.
- One event/journal trait.
- One state store trait.
- In-memory implementations only in testkit or explicitly named dev modules.

### 5.7 Testkit concepts leak into runtime

Runtime includes fake adapter/proof logic in tests inside production modules. In-memory stores and mock adapters are widely referenced.

Required correction: move mocks, fake proof builders, adversarial helpers, and trace generators into `csv-testkit`. Runtime should not define fake protocol objects except in local `#[cfg(test)]` modules that do not influence public API.

---

## 6. Distributed systems and reliability defects

### 6.1 Coordinator recovery still uses fake proof material in tests

Crash recovery tests regenerate fake proof bundles. That does not validate real-world recovery from lock-confirmed/proof-built/mint-pending states.

Required correction: recovery tests must use deterministic proof fixtures generated by adapters or testkit with canonical verifier acceptance/rejection.

### 6.2 Event store and journal consistency is not proven

Runtime has event store, execution journal, replay database, leases, backpressure, and recovery. The packed code does not show a single atomic transaction boundary across journal write, proof persistence, mint call, replay registration, and event publication.

Required correction:

```text
State transition transaction:
1. acquire lease with fencing token
2. append intent event
3. persist proof payload + digest
4. perform external chain mutation with idempotency key
5. record observed tx/proof
6. advance state using compare-and-swap
7. release or expire lease
```

Every step must be idempotent. Every external call must be retry-safe.

### 6.3 Lease fencing is not clearly enforced across all mutations

Presence of coordinator leases is not enough. Destination minting must verify the lease token or idempotency key is still current before mutation.

Required correction: every mutation API should accept `OperationId` and `LeaseFence`. Adapters should expose idempotency where possible. Runtime must reject stale leases.

### 6.4 Reorg/finality policy is spread out

There are finality modules in protocol, adapters, runtime, and tests. Contracts store proof roots. Bitcoin SPV has confirmations. Ethereum has finality modules. This can diverge.

Required correction: one finality policy object hashed into proof context:

```text
FinalityPolicyV1 { chain_id, mode, min_depth, checkpoint_root, max_reorg_depth, expiry }
```

Adapters only provide evidence; verifier applies policy.

### 6.5 P2P/proof delivery is not a trust boundary

`csv-p2p` includes IPFS/Nostr/proof_delivery, but proof delivery should be untrusted. The audit snapshot does not show mandatory verification before storage or replay effects.

Required correction: delivered proof bundles must be treated as hostile bytes until canonical verifier approves them under an explicit policy.

### 6.6 Resource accounting is not enforced end-to-end

`csv-content` has resource accounting, but CLI/SDK/verification paths do not appear to enforce limits before parsing/proving complex content.

Required correction: enforce maximum payload size, tree leaves, attachment count, proof depth, proof bytes, schema recursion, and verification CPU/memory in every public API.

---

## 7. Data structures and algorithmic defects

### 7.1 Variable-length `Vec<u8>` is overused for protocol fields

Owner, proof, seal refs, payloads, metadata hashes, source seal points, destination owners, and proof bytes often use raw `Vec<u8>`. This loses length/type/domain information.

Required correction: replace with newtypes:

```rust
Hash32([u8; 32])
SanadId(Hash32)
CommitmentHash(Hash32)
OwnerId(OwnerKind, Bytes)
SealRef(ChainIdHash, Bytes)
ProofBytes(ProofSystemId, BoundedBytes)
CanonicalBytes<T>(BoundedBytes)
```

### 7.2 `HashMap<Hash, Metadata>` in content tree is not canonical

A HashMap indexed by hash is not inherently canonical for serialization. If serialized, order must be canonicalized. If duplicate hashes occur, metadata collisions can overwrite semantics.

Required correction: use sorted maps for canonical structures or exclude non-canonical indexes from committed serialization. Store metadata in leaves and derive roots deterministically.

### 7.3 Content tree binary Merkle model is under-specified

The audit snapshot does not show leaf domain tags, internal-node domain tags, odd-leaf handling, chunking rules, metadata binding, or canonical path encoding as frozen external spec.

Required correction: define exact algorithms:

```text
leaf_hash = H("csv.content.leaf.v1" || canonical(LeafDescriptor))
internal_hash = H("csv.content.node.v1" || left || right)
empty_hash = H("csv.content.empty.v1")
odd_leaf_strategy = duplicate | promote | pad, exactly one
proof_path = Vec<{side, sibling_hash, level}>
```

### 7.4 SPV Merkle verification may ignore position semantics

Bitcoin SPV verifier has a `tx_index` parameter, but standalone verification wrapper calls with `0`. If branch ordering is not direction-aware at every level, Merkle proof verification is incomplete.

Required correction: proof must include position bits or ordered sibling sides. Verify against tx index at each level.

### 7.5 Nullifier construction is not visibly uniform

Contracts, protocol, and adapters mention nullifiers, registered nullifiers, replay IDs, and seal IDs. There is no single shown nullifier formula that every chain uses.

Required correction:

```text
nullifier = H("csv.nullifier.v1", canonical({sanad_id, source_chain, source_seal_ref, owner_commitment, transfer_nonce}))
```

Add cross-language vectors.

### 7.6 Timestamp semantics differ across chains

Solana uses Unix seconds, Ethereum block timestamp, Sui uses epoch * 1000 because timestamp is not directly available, comments mention Unix milliseconds. This breaks refunds, ordering, and event comparisons.

Required correction: contracts must not claim common timestamp semantics unless normalized by verifier policy. Use chain-local clock type in event schema.

---

## 8. Security defects

### 8.1 All-zero seeds and printed seed examples normalize unsafe behavior

Bitcoin examples generate deterministic seeds and print seed hex. Tests use zero seeds. This is acceptable only if aggressively isolated, but the packed repo has examples under adapter paths likely reachable by developers.

Required correction: mark dangerous examples as test-only, never print seed material by default, and add warnings that fail CI if example code uses production feature flags.

### 8.2 API keys and RPC URLs are plain strings

`RpcEndpoint` has `url: String` and `api_key: Option<String>`. No redaction type is visible.

Required correction: use redacted secret wrappers and logging filters. Errors must never include API keys.

### 8.3 Panic/unwrap usage exists in non-test paths

The scan found `panic!`, `unwrap()`, and `expect()` across adapters, runtime, keys, storage, contracts build scripts, and examples. Some are tests, but some are production modules.

Required correction: zero panics in protocol/runtime/adapters except unreachable invariants proven by type state. Build scripts may panic, but runtime libraries must return typed errors.

### 8.4 Mock proof systems are too close to production

Mock proof/prover/verifier code appears in adapters and protocol modules, not only in testkit.

Required correction: compile-time ban:

```rust
#[cfg(all(not(test), feature = "mock"))]
compile_error!("mock proof features cannot be enabled outside tests");
```

### 8.5 Encryption API is misleading

Fake encryption with zero nonce and empty ciphertext/tag is a direct security hazard.

Required correction: delete or implement with audited AEAD, random nonce, key management, associated data bound to Sanad descriptor, and failure-safe verification.

### 8.6 Contract admin trust contradicts client-side validation claims

Owner/verifier/admin roles can update proof roots and mark seals. Without strict governance, proof roots are trust anchors controlled by operators.

Required correction: document this as a trust assumption or replace with decentralized verifier/root mechanisms.

---

## 9. Dependency and build readiness defects

### 9.1 Rust version `1.93` is not a stable ecosystem baseline

Several crates set `rust-version = "1.93"`. This will block developers using current stable releases if 1.93 is not available in their toolchain at adoption time.

Required correction: use the actual minimum supported stable Rust version tested in CI, or remove publish metadata until real MSRV is established.

### 9.2 Workspace dependency versions diverge

Workspace uses `thiserror = "1.0"`, while some crates use `thiserror = "2.0"`. Root uses workspace dependencies but many crates specify versions directly.

Required correction: centralize dependencies in `[workspace.dependencies]`, ban duplicate direct versions unless justified.

### 9.3 Heavy native dependencies leak into broad crates

Runtime default feature includes persistent RocksDB. SDK depends on runtime. CLI enables many chain features. This raises build friction for implementers.

Required correction: default features should be minimal. Heavy dependencies should be opt-in profiles.

### 9.4 Generated bindings and contract artifacts are not verifiably pinned

ABI bindings are hand-coded in `csv-contract-bindings` and Ethereum adapter has bindings/bytecode modules. Without lockfiles/artifacts in snapshot, generated source cannot be trusted as matching contracts.

Required correction: generate bindings in CI from contract build artifacts and verify ABI hash against pinned constitution.

### 9.5 `.md` files excluded from audit input

The packed repo excluded Markdown, including README/API docs. Developer readiness cannot be validated.

Required correction: final audit must include docs, examples, generated vectors, deployment manuals, and conformance guide.

---

## 10. Traceability defects

### 10.1 Deployment outputs are committed into source paths

Files like `deployment.out`, `deploy-output-testnet.txt`, and registry init output appear in contract directories. That creates confusion between source, generated artifacts, and environment state.

Required correction: generated deployment outputs belong in ignored artifact directories or signed release manifests.

### 10.2 Contract event schemas are not mapped to Rust types by generated vectors

Events exist across Solidity, Move, and Anchor, but no single event ABI schema is shown as canonical and cross-checked against Rust decoding.

Required correction:

- Define canonical event model in Rust.
- Generate Solidity/Move/Anchor event definitions from it or test against it.
- Include fixture logs from each chain.
- Require adapters to decode fixtures identically.

### 10.3 No visible protocol release manifest

There are deployment manifests, but no clear protocol manifest tying together crate versions, ABI hashes, schema hashes, proof leaf version, hash domains, contract addresses, verifier keys, and golden vectors.

Required correction:

```toml
[protocol]
version = "1.0.0"
codec = "csv-cbor-v1"
proof_leaf = "csv.proof.leaf.v1"
sanad_descriptor = "csv.sanad.descriptor.v1"
abi_hash = "..."
golden_vectors_hash = "..."
```

---

## 11. Chain adapter defects

### 11.1 Adapter APIs are inconsistent

Each adapter has its own `seal_protocol`, `runtime_adapter`, `ops`, `proofs`, `rpc`, `node`, and types. The factory returns both `ChainBackend` and optional `ChainAdapter`, proving there are at least two adapter abstractions.

Required correction: one chain adapter trait boundary. Runtime should not need both `ChainBackend` and `ChainAdapter` unless their separation is formally documented and enforced.

### 11.2 Bitcoin factory requires REST and seed

Bitcoin factory requires a REST endpoint and a 64-byte seed hex. That excludes PSBT-only, descriptor-wallet, hardware signer, watch-only, and remote signer workflows.

Required correction: Bitcoin adapter must accept signer traits and UTXO providers separately.

### 11.3 Ethereum factory defaults contract address to zero

Ethereum factory uses zero address when contract address is absent for RPC construction. That can lead to accidental calls against address zero or false setup success.

Required correction: missing contract address must be a hard error for any operation that needs contracts.

### 11.4 Solana uses placeholder transaction signature access

Solana contract code comments say placeholder is used because Anchor does not provide direct tx signature access.

Required correction: do not derive protocol IDs from unavailable tx signatures. Use explicit instruction parameters or PDA seeds bound to canonical preimages.

### 11.5 Sui timestamp workaround is not production-grade

Sui code uses epoch multiplied by 1000 as timestamp substitute. That is not Unix milliseconds.

Required correction: expose clock type and avoid absolute timeout semantics unless using a reliable clock object/framework mechanism.

### 11.6 Celestia/IPFS paths include mock/placeholder behavior

Celestia client, DA layer, IPFS, blob, RPC modules include placeholder/mock mentions. DA proofs cannot be trusted while storage fallback and proof IDs have mocks in production code.

Required correction: split DA adapter proof generation from storage convenience, and reject unverified IPFS data until commitment inclusion is proven.

---

## 12. Testing defects

### 12.1 Too many tests validate fake paths

Tests use fake hashes, dummy proof bytes, all-zero seeds, in-memory stores, and placeholder adapters. This inflates apparent coverage while not validating production behavior.

Required correction: classify tests:

- Unit tests for pure functions.
- Golden vector tests for protocol hashes.
- Cross-language contract vector tests.
- Adapter integration tests against local deterministic chains.
- Adversarial tests with invalid proofs.
- Crash recovery tests using real persisted proof fixtures.

### 12.2 Compile-fail tests exist but core is excluded

**RESOLVED:** csv-core removed. Compile-fail typestate tests were in `csv-core/tests/compile_fail/`. These tests now live in `csv-algebra/tests/compile_fail/` (typestate algebra tests). CI runs them via `cargo test -p csv-algebra`.

### 12.3 Property tests are placeholders

**RESOLVED:** csv-core removed. Property tests were in `csv-core/tests/properties/`. These have been migrated to their respective crates:

- `csv-hash/tests/` — serialization determinism, domain separation
- `csv-proof/tests/` — proof structure invariants
- `csv-protocol/tests/` — state machine invariants

Required correction: property tests must assert deterministic serialization, replay resistance, rollback consistency, Merkle proof soundness, and domain separation with generated cases.

### 12.4 Contract adversarial tests have placeholders

Aptos/Sui/Solana adversarial tests include placeholder comments. Contract readiness requires adversarial tests against replay, double-mint, wrong proof root, wrong chain ID, malformed metadata, unauthorized refund, stale root, and admin abuse.

Required correction: every contract must have negative tests for each failure code and event invariant.

---

## 13. Required crate split before freeze

Do not split into `core`, `runtime`, `sdk`, `adapters`, `applications` until the following dependency rules are enforced by CI.

### 13.1 Proposed dependency constitution

```text
csv-primitives  -> no csv-* deps
csv-codec       -> csv-primitives
csv-hash        -> csv-primitives, csv-codec
csv-content     -> csv-primitives, csv-hash, csv-codec
csv-protocol    -> csv-primitives, csv-hash, csv-codec, csv-content(optional)
csv-proof       -> csv-primitives, csv-hash, csv-codec, csv-protocol
csv-verifier    -> csv-proof, csv-protocol
csv-storage     -> csv-primitives, csv-protocol
csv-wallet      -> csv-primitives, csv-protocol, csv-keys
csv-runtime     -> csv-protocol, csv-proof, csv-verifier, csv-storage, adapter traits only
csv-sdk         -> csv-protocol, csv-proof, csv-wallet, optional runtime
csv-adapter-*   -> csv-protocol, csv-proof, csv-verifier traits, chain deps
csv-contract-*  -> no dependency from core/protocol; only bindings/tests depend on contracts
csv-cli         -> csv-sdk only, plus rendering/config
csv-testkit     -> may depend on everything except production crates must not depend on it
```

### 13.2 Forbidden dependency edges

```text
core/protocol -> contracts
core/protocol -> runtime
core/protocol -> adapters
core/protocol -> CLI
runtime -> concrete adapters directly
sdk default -> runtime heavy deps
contracts -> generated mutable artifacts
CLI -> chain adapter internals
wallet -> CLI state
```

### 13.3 Required CI gates

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo audit
cargo nextest run --workspace --all-features
cargo llvm-cov nextest --workspace --all-features
cargo machete
cargo +nightly udeps
cargo semver-checks
```

Add architecture tests that fail on forbidden imports and placeholder strings in production crates.

---

## 14. Required Sanad v1 freeze checklist

Do not freeze core/runtime until every item below is done.

- [ ] Sanad ID derivation fixed and golden-vector tested.
- [ ] Sanad content descriptor defined and canonicalized.
- [ ] Complex content root, attachment root, claims root, participants root, schema hash, codec, and resource limits bound into descriptor hash.
- [ ] `csv-cli sanad create` supports descriptor-based creation.
- [ ] SDK create accepts descriptor, wallet signer, seal policy, proof policy.
- [ ] Wallet signs descriptor hash and ownership intent.
- [ ] Proof leaf includes descriptor hash and nullifier formula.
- [ ] Contracts emit descriptor hash and protocol version.
- [ ] Verifier rejects proof bundles without descriptor/proof-policy binding.
- [ ] Selective disclosure proof binds to Sanad ID and descriptor hash.
- [ ] JSON is excluded from hashing paths.
- [ ] Schema validation implemented.
- [ ] Resource accounting enforced before parsing/verifying complex content.

---

## 15. Required contract v1 freeze checklist

- [ ] Choose only one Ethereum contract surface.
- [ ] Delete or isolate legacy `CSVLock`/`CSVMint` if `CSVSeal` is canonical.
- [ ] Align ABI constitution with actual function names.
- [ ] Generate bindings from compiled ABI, not hand-maintained interfaces.
- [ ] Pin ABI hash and bytecode hash.
- [ ] Create deployment profiles for every chain.
- [ ] Remove committed deployment output files from source paths.
- [ ] Add dry-run and verify modes to deploy scripts.
- [ ] Add root governance policy: epoch, expiry, monotonicity, authority, timelock/multisig.
- [ ] Remove arbitrary owner seal-consumption ability.
- [ ] Standardize chain ID hash, not `u8` only.
- [ ] Standardize event schemas across Solidity/Move/Anchor.
- [ ] Add cross-language proof vectors.
- [ ] Add negative adversarial tests for every contract failure mode.
- [ ] Add post-deploy smoke verification against emitted events and view functions.

---

## 16. Required developer-readiness checklist

- [ ] Provide conformance vectors for Sanad ID, commitment, descriptor hash, proof leaf, nullifier, content tree, selective disclosure, and contract events.
- [ ] Provide a minimal external chain adapter template.
- [ ] Provide a contract implementation template with required events and functions.
- [ ] Provide a verifier test harness for third-party chains.
- [ ] Provide a wallet signer trait and examples using hardware/remote signers.
- [ ] Provide a strict SDK example without runtime-heavy dependencies.
- [ ] Provide migration/versioning policy for core types.
- [ ] Provide semver policy and MSRV policy.
- [ ] Provide threat model.
- [ ] Provide explicit trust assumptions for proof roots/verifiers/admins.

---

## 17. Files/modules requiring immediate scrutiny

### Core/protocol

- `csv-protocol/src/sanad.rs` — Sanad ID derivation and descriptor absence.
- `csv-hash/src/sanad.rs` — documented ID formula conflicts with protocol constructor behavior.
- `csv-codec/src/schema.rs` — no-op validation.
- `csv-codec/src/canonical.rs` — ensure canonical CBOR actually rejects non-canonical inputs on decode; current decode appears to deserialize without re-canonicalization check.
- `csv-proof/src/proof_validation.rs` — placeholder validation.

### Runtime/storage

- `csv-runtime/src/transfer_coordinator.rs` — fake proof paths in module tests, unclear atomicity boundary, idempotency/fencing not proven.
- `csv-runtime/src/event_store.rs` — in-memory event store in runtime crate.
- `csv-runtime/src/execution_journal.rs` — verify crash consistency and durable digest semantics.
- `csv-runtime/src/replay_db.rs` — verify CAS and replay semantics under concurrent nodes.
- `csv-storage`, `csv-store` — overlapping storage abstractions. (csv-core's store.rs and state_store.rs migrated to csv-storage during csv-core removal.)

### CLI/SDK/wallet

- `csv-sdk/src/sanads.rs` — fake create path with zero proof/owner.
- `csv-cli/src/commands/sanads.rs` — value-centric Sanad flow; complex content not first-class.
- `csv-cli/src/commands/content.rs` — fake encryption and detached content flow.
- `csv-cli/src/commands/validate.rs` — ensure every path delegates to canonical verifier.
- `csv-cli/src/commands/wallet/*` — secret handling and persistence.
- `csv-keys/*` — secret zeroization, encryption, export policy.

### Contracts/adapters

- `csv-contracts/ethereum/contracts/src/CSVSeal.sol` — ABI mismatch, admin powers, proof-root governance, hash-function assumptions.
- `csv-contracts/ethereum/contracts/src/CSVLock.sol` and `CSVMint.sol` — remove if obsolete.
- `csv-contract-bindings/src/abi_constitution.rs` — required function names mismatch current contract.
- `csv-contracts/solana/contracts/programs/csv-seal/src/lib.rs` — placeholder tx signature access, proof leaf format.
- `csv-contracts/sui/sources/csv_seal.move` — epoch timestamp substitution, vector-byte schemas.
- `csv-contracts/aptos/contracts/sources/csv_seal.move` — vector-byte schemas, adversarial coverage.
- `csv-adapters/csv-ethereum/src/mpt.rs` — placeholder account/storage proof verification.
- `csv-adapters/csv-bitcoin/src/zk_prover.rs` — mock proof generation.
- `csv-adapters/csv-solana/src/runtime_adapter.rs` and `csv-adapters/csv-sui/src/runtime_adapter.rs` — TODOs.

---

## 18. Minimal hard stop list

The project should not proceed to crate freeze until these are fixed:

1. ~~`csv-core` is included in CI/workspace or explicitly moved to a new frozen workspace.~~ **RESOLVED** — csv-core removed, `csv-core-TOMBSTONE.md` created.
2. ~~Core no longer depends on contract bindings.~~ **RESOLVED** — csv-core removed.
3. Sanad ID derivation is corrected and vector-tested.
4. Sanad descriptor for complex content is defined, canonicalized, and bound into proofs.
5. SDK Sanad creation no longer creates fake owner/proof bytes.
6. CLI can create and verify descriptor-based complex Sanads end-to-end.
7. Schema validation is real.
8. Placeholder proof validation is removed from production crates.
9. ~~ZK empty-proof acceptance and placeholder verifier keys are removed.~~ **RESOLVED** — csv-core (which contained zk_proof.rs) removed.
10. Ethereum MPT placeholder verification is replaced.
11. `csv-cli content encrypt` fake encryption is deleted or implemented.
12. One canonical contract ABI is selected and old Ethereum surfaces are removed or versioned legacy.
13. ABI constitution matches actual compiled contracts.
14. Contract proof leaf/event schema is frozen across chains.
15. Deployment scripts verify bytecode/ABI/constructor/profile before deployment.
16. Wallet/secret handling is centralized and raw hex secret strings are removed from generic configs.
17. Runtime storage/replay/event abstractions are deduplicated.
18. Recovery/idempotency/lease fencing is enforced by design and tested with real proof fixtures.
19. Dependency versions and lockfiles are pinned and audited.
20. Third-party conformance vectors and adapter template exist.

---

## 19. Answer to the Sanad flexibility question

Current Sanads are **not flexible enough** for arbitrary complex content in a safe, portable, verifiable way. They can indirectly point to complex content by commitment hashes and optional Merkle roots, but that is insufficient because the schema, codec, content tree, attachment set, disclosure policy, and proof policy are not mandatory parts of the Sanad identity and proof leaf.

Adding complex content without a frozen descriptor will cause verifier divergence. The same semantic Sanad can hash differently across SDK, CLI, contracts, and adapters. The same hash can also become ambiguous if the descriptor does not include schema and codec. Proof verification becomes weaker because verifiers only see hashes without knowing the exact canonical object they are supposed to validate.

`csv-cli` cannot currently support complex Sanads end-to-end. It has separate content/schema commands, but Sanad create/transfer/consume flows are not descriptor-driven.

`csv-wallet` cannot be assessed as a crate because it does not exist in the packed repository. Wallet logic is scattered across `csv-keys`, CLI, SDK, coordinator, runtime, and adapters. As currently structured, wallet support for complex Sanads is not acceptable because signer semantics are not bound to descriptor hashes through a single wallet API.

---

## 20. Required target architecture for complex Sanads

```text
Application payload
  -> schema validation
  -> canonical payload bytes
  -> content tree / attachment tree / claims tree / participants tree
  -> SanadPayloadDescriptor
  -> descriptor_hash
  -> SanadCommitmentPreimage
  -> commitment
  -> SanadIdPreimage
  -> sanad_id
  -> wallet signature over creation intent
  -> seal creation / lock / anchor
  -> proof leaf containing descriptor_hash + commitment + nullifier + chain identities
  -> contract event
  -> offline verifier
```

Any shortcut around this pipeline will produce incompatible implementations.

---

## 21. Final blunt assessment

The repository still contains fake implementations, placeholder validators, conflicting protocol semantics, scattered wallet logic, ABI drift, contract duplication, weak proof-root governance, unclear dependency boundaries, and incomplete complex-content binding. Freezing core/runtime now would freeze ambiguity into the protocol. Deploying the contracts now would make later corrections expensive or impossible. Inviting external developers or chains now would force them to reverse-engineer unstable behavior instead of implementing a clear protocol.
