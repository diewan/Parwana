# AGENT.md — CSV Protocol AI Engineering Rules

## Mission

You are working on a security-critical cross-chain protocol.

Your task is NOT to make code compile.
Your task is to preserve protocol invariants and eliminate unsafe states.

Compilation success alone is NOT evidence of correctness.

---

# 1. Core Security Invariants

These are mandatory and non-negotiable.

1. No fabricated blockchain state.
2. No placeholder verification.
3. No bypass paths around verification/runtime/state machine.
4. No replayable transfers.
5. No mint without verified inclusion + verified finality.
6. No raw hashing in protocol logic.
7. No silent fallback behavior.
8. No partial validation.
9. No downgrade from error → warning for security failures.
10. All state transitions must be monotonic and explicit.
11. Finality is NEVER optional — all runtime modes enforce strict finality.
12. CLI holds NO protocol authority state — all delegated to csv-runtime.

---

# 2. Forbidden Patterns

The following are forbidden in production code:

```rust
todo!()
unimplemented!()
unwrap()
expect()
unsafe
new_unchecked()

Ok(true)
Ok(Default::default())

assert!(true)

Sha256::digest
Keccak256::digest
blake3::hash
```

Forbidden outside:

* /tests
* /fuzz
* /benches

Also forbidden:

* fake proofs
* mock signatures
* placeholder crypto
* empty verification
* "temporary" production fixes

Never remove logic merely to satisfy the compiler.

---

# 3. Verification Rules

Every verification path MUST:

* reject missing data,
* reject malformed proofs,
* reject empty proof bundles,
* perform actual cryptographic verification,
* return Err(...) on verification failure.

Verification code may NEVER:

* silently pass,
* fallback,
* infer success from missing fields,
* substitute defaults.

`Ok(true)` in verification paths is forbidden.

---

# 4. Runtime Architecture Rules

Applications MUST use:

* csv-runtime
* TransferCoordinator
* unified runtime verification/state flow
* ExecutionJournal for crash-safe phase tracking

Applications MUST NOT:

* call adapters directly,
* bypass runtime state machine,
* mint directly,
* skip replay protection,
* skip seal registry validation,
* store leases or transfer state in CLI.

Security abstractions that are not wired into production paths are considered FAILED implementations.

---

# 5. Mandatory Execution Protocol

## 5.1 Repository-Wide Search

Before fixing anything:

1. search the repository for equivalent patterns,
2. enumerate all occurrences,
3. classify production vs test usage,
4. patch all production occurrences,
5. verify no bypass path remains.

Fixing only one occurrence is forbidden.

---

## 5.2 Transitive Verification

After every change verify:

* old code paths removed,
* deprecated APIs unreachable,
* runtime actually invokes new logic,
* CI checks target real crate/module names,
* applications cannot bypass protections.

Unused security code does not count as implemented.

---

## 5.3 Adversarial Review

Before declaring completion ask:

* How can this still fail?
* Can an attacker bypass this elsewhere?
* Does any legacy path remain callable?
* Can CI silently miss this?
* Can malformed proofs still pass?
* Can replay still occur concurrently?

You MUST attempt to break your own implementation.

---

## 5.4 Proof Obligations

Do not declare completion without:

* tests,
* negative tests,
* grep/ripgrep verification,
* invariant verification,
* regression prevention,
* CI enforcement where applicable.

---

# 6. Required Testing

Every security fix MUST include:

* positive test,
* malformed-input test,
* replay/double-use test where applicable,
* invariant regression test.

Verification fixes REQUIRE malformed proof rejection tests.

---

# 7. CI Enforcement Requirements

CI MUST fail on:

* TODO/FIXME
* unwrap()/expect()
* unsafe outside approved modules
* Result<bool> in verification paths
* Ok(true) in verification paths
* raw hashing
* direct adapter imports from applications
* fake/mock crypto in production code

Compile-fail tests are preferred over grep checks whenever possible.

---

# 8. Dependency Boundaries

Applications:

* MUST depend on csv-runtime
* MUST NOT depend directly on chain adapters

Wallet/UI code may not orchestrate transfers directly.

Transfer orchestration belongs exclusively to:

* TransferCoordinator

**Architecture layering:**

* `csv-algebra` — pure no_std typestate algebra (no dependencies on csv-wire or any serialization)
* `csv-wire` — owns ALL serde, ALL transport encoding, ALL RPC wire format conversions
* `csv-protocol` — protocol orchestration layer (no serialization logic)
* `csv-codec` — canonical CBOR serialization (deterministic encoding)
* `csv-coordinator` — per-chain execution cells (isolated failure domains)
* `csv-admission` — admission control (zero chain adapter dependencies)
* `csv-runtime` — depends only on csv-protocol/csv-core (no direct chain adapter imports)
* `csv-verifier` — depends on csv-protocol + csv-proof + csv-hash (no csv-core dependency)

**Forbidden dependencies:**

* `csv-algebra` MUST NOT depend on `csv-wire` (enforced by deny.toml)
* `csv-core` MUST NOT depend on any chain adapter
* `csv-cli` MUST NOT import chain adapters directly
* `csv-runtime` MUST NOT import chain adapters directly
* `serde_json` is forbidden in canonical hashing paths (use canonical_cbor)

## Current Codebase Structure

**Phase 1 restructuring crates:**

* `csv-algebra` — pure no_std typestate algebra for transfer state machine
* `csv-wire` — wire encoding and transport layer (owns all serde/transport encoding)
* `csv-protocol` — protocol orchestration layer
* `csv-codec` — canonical serialization (CBOR)
* `csv-hash` — hash types, SanadId, replay ID types
* `csv-proof` — proof bundle types, replay ID derivation
* `csv-verifier` — canonical proof verification
* `csv-schema` — schema definitions
* `csv-content` — content types
* `csv-storage` — storage traits and backends (RocksDB, PostgreSQL, in-memory)
* `csv-testkit` — test fixtures and adversarial testing
* `csv-contract-bindings` — smart contract bindings
* `csv-coordinator` — per-chain execution cells with isolated failure domains
* `csv-admission` — admission control and pressure boundaries

**Legacy crates:**

* `csv-core` — legacy protocol types (migration in progress)
* `csv-runtime` — TransferCoordinator, lease management, replay DB, circuit breakers, execution journal (depends only on csv-core/csv-protocol)
* `csv-sdk` — public SDK facade
* `csv-cli` — CLI binary (stateless, delegates to runtime)
* `csv-keys` — key management
* `csv-store` — legacy state storage
* `csv-p2p` — peer-to-peer networking
* `csv-observability` — metrics and observability

**Chain adapters** (under `csv-adapters/`):
`csv-bitcoin`, `csv-ethereum`, `csv-solana`, `csv-sui`, `csv-aptos`, `csv-celestia`

**Not in workspace:** `csv-mcp-server/`, `csv-examples/`

**Does not exist:** `csv-wallet/`, `csv-explorer/`, `typescript-sdk/`

**Documentation:** `csv-docs/` (not `docs/`)

---

# 9. Completion Criteria

A task is complete ONLY IF:

* all invariant violations are eliminated,
* all production paths updated,
* no bypass path remains,
* no legacy insecure path remains reachable,
* tests pass,
* CI protections exist,
* equivalent anti-patterns are removed repository-wide.

"Compiles successfully" is NOT completion.

---

# 10. Agent Behavior Rules

Never:

* simplify cryptographic structures to satisfy types,
* replace proofs with bytes,
* delete validation logic,
* weaken invariants,
* postpone security work,
* leave dead security code,
* leave stub implementations.

If architecture prevents correctness:
REFactor the architecture.
Do not weaken the protocol.
