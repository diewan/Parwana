# AUDIT.md

## Scope

Repository-wide architectural, protocol, security, verification, contract, runtime, SDK, wallet, CLI, and distributed-system audit based on the supplied repository snapshot.

This audit intentionally excludes praise. Every section focuses on risk, weakness, inconsistency, future migration hazards, architectural impurity, scalability constraints, protocol ambiguity, and operational danger.

---

# 1. Critical Architectural Findings

## 1.1 The Repository Is Still a Monolith Pretending to Be Modular

The workspace is visually split into crates, but architecturally it still behaves like a monolith.

Problems:

- `csv-core` contains protocol definitions, runtime semantics, replay logic, transfer states, verification logic, chain abstractions, VM abstractions, persistence abstractions, event abstractions, and recovery semantics simultaneously.
- Runtime concepts leak into SDKs and adapters.
- Chain adapters duplicate proof/finality/seal abstractions instead of implementing strict capability traits.
- Contracts are chain-specific but protocol semantics are not canonically defined in one place.
- Wallet, CLI, explorer, SDK, runtime, and contracts all define overlapping semantic concepts.
- There is no single canonical specification boundary.

Consequence:

You do not yet have a stable protocol kernel.
You have a distributed semantic drift problem.

If independent teams begin implementing adapters today, they will diverge.

---

## 1.2 Protocol Semantics Are Underspecified

The repository contains:

- `PROTOCOL_CONSTITUTION.md`
- `PROTOCOL_INVARIANTS.md`
- `THREAT_MODEL.md`

But the codebase still lacks:

- A machine-verifiable protocol specification.
- Canonical binary encoding spec.
- Canonical hashing spec versioning.
- Canonical deterministic serialization constraints.
- Explicit byte-order guarantees across all domains.
- Mandatory domain separation registry.
- Canonical Merkle construction specification.
- Formal replay semantics.
- Canonical transition legality matrix.
- Finality semantics per chain.
- Fork/reorg conflict resolution specification.

This means the implementation currently defines the protocol.
That is extremely dangerous before ecosystem adoption.

The protocol spec must define the implementation.

---

## 1.3 You Are Mixing "Transport Proofs" and "Protocol Proofs"

Multiple crates mix:

- inclusion proofs
- state proofs
- replay proofs
- chain finality proofs
- ownership proofs
- commitment proofs
- cross-chain proofs
- zk proofs

without a rigid proof taxonomy.

This creates future incompatibility.

You need:

```text
Proof
 ├── TransportProof
 ├── InclusionProof
 ├── FinalityProof
 ├── OwnershipProof
 ├── TransitionProof
 ├── ReplayProof
 ├── ExecutionProof
 ├── ZKProof
 └── CompositeProofBundle
```

Currently proof semantics are scattered.

Examples:

- `csv-core/proof.rs`
- `proof_bundle.rs`
- `proof_material.rs`
- `proof_pipeline.rs`
- `proof_provenance.rs`
- chain-local `proofs.rs`

This fragmentation will eventually create incompatible verification paths.

---

## 1.4 Chain Adapters Are Not Pure Adapters

Adapters currently contain:

- configuration
- verification
- finality assumptions
- proof semantics
- wallet logic
- transaction logic
- RPC logic
- mint logic
- seal logic
- protocol semantics

This violates adapter isolation.

Adapters should only:

```text
- translate chain primitives
- submit transactions
- fetch proofs
- verify chain-native finality
- expose deterministic capabilities
```

Instead adapters are becoming mini runtimes.

This will become unmaintainable after adding more chains.

---

## 1.5 There Is No Strong Capability Model

Chains differ fundamentally:

| Chain | Model |
|---|---|
| Bitcoin | UTXO |
| Ethereum | Account |
| Solana | Account + Program |
| Sui | Object |
| Aptos | Resource |
|

Yet the codebase attempts to unify them too early.

This is dangerous.

You need capability traits instead of semantic flattening.

Examples:

```rust
trait HasFinalityProof
trait HasEventProof
trait HasStateRoot
trait HasObjectOwnership
trait HasReplayProtection
trait HasDeterministicExecution
```

Instead, many abstractions currently assume all chains can support similar semantics.

They cannot.

---

# 2. Sanad Design Audit

## 2.1 Current Sanad Model Is Too Weakly Typed

Current structure appears optimized for:

- hashes
- commitments
- ownership transfer
- proof linkage

But not for:

- rich semantic content
- structured metadata
- embedded claims
- attestations
- multi-party state
- legal artifacts
- nested provenance
- graph-linked objects
- selective disclosure
- encrypted subtrees
- streaming content
- large content references
- composable rights

The current model risks becoming a glorified commitment envelope.

---

## 2.2 Complex Content Support Is Not Properly Defined

You asked whether Sanads can support complex content.

Current answer:

Not safely.

You can technically serialize arbitrary content, but the protocol semantics are not mature enough to guarantee:

- deterministic hashing
- canonical encoding
- stable verification
- long-term compatibility
- selective verification
- schema migration
- partial disclosure
- merkleized content
- incremental updates
- streaming verification

Without canonicalization, complex Sanads will fracture verification ecosystems.

---

## 2.3 You Need a Canonical Content Layer

Current design lacks:

```text
Sanad
 ├── Header
 ├── ContentDescriptor
 ├── SchemaID
 ├── EncodingID
 ├── CompressionID
 ├── EncryptionDescriptor
 ├── ContentRoot
 ├── AttachmentRefs
 ├── ProofBundle
 └── SealRefs
```

Currently content semantics appear implicit.

That is not sustainable.

---

## 2.4 CSV Wallet and CLI Are Not Ready for Complex Sanads

Current wallet and CLI architecture strongly suggest:

- form-driven workflows
- fixed proof assumptions
- static verification models
- predefined views

Problems:

- no schema registry
- no dynamic renderer system
- no typed plugin system
- no partial content verification
- no streaming attachment verification
- no schema evolution strategy
- no canonical content negotiation

If Sanads become complex:

- wallet performance will collapse
- verification latency will explode
- proof bundles will become huge
- storage abstraction will fail
- UI rendering becomes unsafe
- deterministic serialization becomes fragile

---

## 2.5 You Need Merkleized Content Trees

Large or complex Sanads should never hash entire payloads monolithically.

You need:

```text
SanadContentTree
 ├── Metadata
 ├── Claims
 ├── Attachments
 ├── Rights
 ├── Participants
 ├── Signatures
 ├── RedactedSubtrees
 └── EncryptedSubtrees
```

Each subtree must:

- hash independently
- support selective proof generation
- support selective disclosure
- support detached storage
- support streaming validation

Without this, large Sanads will become impossible to verify efficiently.

---

## 2.6 Canonical Serialization Is Still Dangerous

I see many `to_vec()` implementations.

That is a red alert.

Examples:

- `BitcoinSealPoint::to_vec`
- `AptosSealPoint::to_vec`

Problems:

- manual serialization
- implicit endianness
- no version tags
- no canonical ordering enforcement
- no field evolution guarantees
- no forward compatibility
- no schema binding

This is protocol fragility.

You need a canonical encoding layer.

Prefer:

- DAG-CBOR
- deterministic CBOR
- SSZ
- canonical protobuf
- custom fixed binary format with strict spec

But never ad hoc `to_vec()` protocol serialization.

---

# 3. Proof and Verification Audit

## 3.1 Verification Semantics Are Fragmented

Verification logic exists in:

- adapters
- runtime
- wallet
- SDK
- explorer
- contracts

This guarantees divergence.

You need:

```text
csv-core-verifier
```

as the ONLY canonical verifier.

Everyone else should call it.

---

## 3.2 No Explicit Verification Context Model

Verification depends on:

- chain state
- protocol version
- runtime policy
- replay registry
- chain finality
- trusted checkpoints
- schema registry
- adapter implementation

But these dependencies are mostly implicit.

You need:

```rust
struct VerificationContext
```

with explicit:

- protocol version
- chain capabilities
- trusted roots
- finality policy
- replay policy
- schema registry
- verification mode

Without this, independent implementations will verify differently.

---

## 3.3 Finality Semantics Are Naive

Examples:

- Bitcoin: confirmations
- Aptos: validator certification
- Solana: commitment levels
- Ethereum: probabilistic finality
- Sui: checkpoint finality

The repository currently treats these too uniformly.

This is protocol-risky.

You need explicit finality classes.

```text
ProbabilisticFinality
EconomicFinality
CheckpointFinality
ValidatorQuorumFinality
InstantFinality
```

Otherwise proofs from different chains are incomparable.

---

## 3.4 Replay Protection Is Incomplete

Replay logic exists across:

- replay registry
- replay store
- replay DB
- nullifiers
- seals

But there is no globally enforced replay invariant.

Risk:

- double consumption
- cross-chain replay
- proof reuse
- stale proof resurrection
- rollback replay
- delayed finality replay

Replay must be protocol-central.
Not adapter-central.

---

## 3.5 Reorg Handling Is Architecturally Dangerous

The existence of:

- rollback states
- reconciliation
- adversarial runtime
- reorg detector
- rollback recovery

means the protocol is acknowledging unstable state.

But:

- invariants are not formally enforced
- rollback semantics are not canonicalized
- proof invalidation rules are unclear
- finality downgrade behavior is unclear
- cross-chain rollback behavior is unclear

This is one of the highest risk areas in the repository.

---

# 4. csv-contracts Audit

## 4.1 Contracts Are Too Thin Semantically

Current contracts appear to mostly:

- register seals
- mint
- lock
- emit events

Problems:

- insufficient semantic anchoring
- weak replay enforcement
- limited provenance tracking
- weak schema awareness
- weak version awareness
- no canonical content binding
- limited future extensibility

They currently look like storage/event contracts rather than protocol-critical verification anchors.

---

## 4.2 Contracts Lack Upgrade Strategy

You said contract upgrades are not feasible.

Current architecture is not ready for immutability.

Missing:

- explicit storage versioning
- upgrade-safe layout guarantees
- event schema guarantees
- protocol compatibility registry
- feature negotiation
- deprecation framework
- immutable verification commitments

Without these, future protocol evolution becomes dangerous.

---

## 4.3 Event Semantics Are Too Weak

Contracts should emit:

```text
ProtocolVersion
SchemaVersion
ContentRoot
ProofRoot
SealRoot
ReplayDomain
TransitionType
PreviousCommitment
```

If not emitted on-chain, external indexers become trusted interpreters.

That is unacceptable.

---

## 4.4 Missing Deterministic Hash Registry

All contracts must share:

- exact hashing algorithm
- exact serialization
- exact domain separation
- exact encoding
- exact field ordering

I do not see evidence of a formal hash registry.

This creates catastrophic multi-chain divergence risk.

---

## 4.5 Deployment Scripts Are Operationally Weak

Scripts exist but appear simplistic.

Missing:

- deterministic deployment manifests
- chain-state verification
- bytecode integrity checks
- deployment reproducibility
- config checksums
- environment pinning
- RPC quorum verification
- rollback safety
- deployment provenance

A deployment system is part of protocol security.

---

## 4.6 Contract ABI Stability Is Not Formalized

If external ecosystems integrate:

- changing event fields
- changing layouts
- changing serialization
- changing proof expectations

will break ecosystems.

You need:

```text
Contract ABI Constitution
```

before freezing contracts.

---

## 4.7 Cross-Chain Semantic Equivalence Is Not Guaranteed

Current contracts are chain-native implementations.

But there is no evidence they enforce equivalent semantics.

Risk:

- different replay behavior
- different finality assumptions
- different ownership guarantees
- different ordering semantics
- different proof binding

This is fatal for interoperability.

---

# 5. Security Audit

## 5.1 Manual Serialization Is a Security Risk

Any protocol-level manual serialization is dangerous.

Reasons:

- version drift
- endianness mismatch
- canonicalization bugs
- hash collisions through ambiguity
- inconsistent encoding across languages

This is one of the largest long-term risks.

---

## 5.2 Hash Domain Separation Is Not Strong Enough

I see tagged hashing usage.

But I do not see:

- global registry
- reserved namespaces
- collision governance
- mandatory tag uniqueness
- tag versioning
- chain-specific namespaces

This becomes dangerous once third parties extend the protocol.

---

## 5.3 Dangerous Default Configurations

Examples:

- localhost RPC defaults
- fake/test signatures in examples
- permissive defaults
- simplistic validation

Risk:

- insecure production deployments
- developers copying examples into production
- accidental trust assumptions

---

## 5.4 Signature Verification Layer Is Too Thin

Example:

`verify_bitcoin_signature`

Problems:

- no policy separation
- no anti-malleability policy enforcement visibility
- no sighash semantics
- no script-context binding
- no explicit domain separation
- no transcript binding

Current verification is cryptographically valid but protocol-weak.

---

## 5.5 No Canonical Trust Model Layer

The repository contains:

- trust packages
- proof provenance
- replay stores
- finality
- monitoring

But there is no unified trust model abstraction.

Critical missing concepts:

```text
TrustedRoot
TrustedCheckpoint
TrustedSigner
TrustedQuorum
TrustedSchema
TrustedExecutionEnvironment
```

---

## 5.6 Explorer and Indexer Become Trusted Infrastructure

Current architecture implicitly trusts:

- explorer indexing
- off-chain proof aggregation
- event reconstruction
- proof storage

This creates hidden centralization.

Verification must remain independently reproducible.

---

## 5.7 No Resource Exhaustion Strategy

Complex Sanads introduce:

- proof explosion
- recursion depth
- attachment amplification
- decompression bombs
- Merkle amplification
- malicious schemas
- pathological graph structures

I see no explicit resource accounting model.

You need:

```text
verification gas / cost accounting
```

for every verification path.

---

# 6. Distributed Systems Audit

## 6.1 Runtime Is Becoming a Consensus System Without Admitting It

The runtime already contains:

- event bus
- replay DB
- lease coordinator
- adversarial handling
- reconciliation
- transfer coordinator
- rollback handling

This is no longer a simple runtime.

It is evolving toward a distributed coordination system.

But:

- no consensus assumptions are documented
- no CAP tradeoff definitions
- no consistency guarantees
- no failure-domain isolation
- no Byzantine assumptions
- no exactly-once semantics
- no durable ordering guarantees

This is dangerous.

---

## 6.2 Eventual Consistency Semantics Are Undefined

Questions currently unanswered:

- what is authoritative state?
- what wins after rollback?
- when is a transfer irreversible?
- can proofs become invalid?
- can ownership revert?
- can replay entries rollback?

Without formal consistency semantics, integrators will implement incompatible assumptions.

---

## 6.3 Runtime Persistence Is Weakly Abstracted

You currently have:

- postgres
- rocksdb
- stores
- state stores
- event stores
- replay stores

But the persistence model is not formally separated.

Danger:

storage semantics leak into protocol semantics.

---

## 6.4 No Explicit Failure Domains

There is no visible architectural separation between:

- verifier failure
- chain RPC failure
- finality uncertainty
- storage corruption
- replay DB corruption
- indexer lag
- partial proof construction
- event ordering failure

These need independent failure-domain models.

---

# 7. Code Purity Audit

## 7.1 Massive Semantic Duplication

The repository contains repeated concepts:

- proofs
- seals
- verifiers
- signatures
- configs
- types
- runtime state
- transfer state
- chain abstractions

across many crates.

This guarantees drift.

---

## 7.2 Naming Drift Already Exists

Examples:

- `seal_ref`
- `seal_point`
- `anchor`
- `commit_anchor`
- `proof_bundle`
- `proof_material`
- `proof_pipeline`

This is early-stage semantic entropy.

You need a protocol glossary enforced at compile-time and documentation-time.

---

## 7.3 Too Many Files Indicate Conceptual Instability

`csv-core` has excessive fragmentation.

This usually means:

- concepts are still moving
- boundaries are unclear
- abstractions are not settled
- responsibilities overlap

Do not freeze runtime/core yet.

It is not stable enough.

---

## 7.4 Runtime State Explosion

Transfer states include:

- awaiting_finality
- completed
- compromised
- locked
- minting
- proof_building
- proof_validated
- rolled_back

This is already approaching unmanageable state-machine complexity.

Missing:

- formal transition graph generation
- exhaustive model checking
- forbidden transition proofs
- temporal property verification

You are relying too heavily on compile-fail tests.

---

## 7.5 Excessive Runtime Intelligence

The runtime is accumulating:

- coordination
- verification
- recovery
- reconciliation
- replay handling
- orchestration
- policy

This eventually becomes impossible to reason about.

Protocol logic must move downward into deterministic core.

---

# 8. Scalability Audit

## 8.1 Verification Costs Will Explode

Complex Sanads + cross-chain proofs + Merkle structures + zk proofs create:

- large proof bundles
- recursive verification
- network amplification
- storage amplification
- CPU amplification
- memory amplification

Current architecture does not appear designed for:

- streaming verification
- incremental verification
- proof caching
- partial verification
- parallel deterministic execution

---

## 8.2 Explorer Architecture Will Not Scale

Explorer currently couples:

- indexing
- storage
- APIs
- websocket streaming
- GraphQL
- UI assumptions

Missing:

- partitioning strategy
- archival strategy
- proof indexing strategy
- content-addressable storage
- immutable proof storage
- event compaction
- checkpoint snapshots

---

## 8.3 RPC Trust Assumptions Are Dangerous

Current configs rely heavily on RPC endpoints.

Missing:

- quorum RPC
- trust scoring
- proof-of-response
- anti-eclipse logic
- Byzantine endpoint handling
- state consistency validation

One malicious RPC can poison verification.

---

# 9. Wallet Audit

## 9.1 Wallet Is Overloaded

Wallet currently includes:

- chains
- services
- proof generation
- proof verification
- zk proofs
- transfers
- storage
- encryption
- onboarding
- networking
- UI

This is architectural overload.

Wallet should not become a runtime.

---

## 9.2 Dynamic Content Is Unsafe

Complex Sanads require:

- schema sandboxing
- attachment sandboxing
- deterministic rendering
- content validation
- secure decompression
- MIME restrictions
- rendering isolation

None of this appears formalized.

---

## 9.3 Local Storage Model Is Weak

Wallet storage abstractions exist but:

- durability guarantees unclear
- corruption recovery unclear
- replay recovery unclear
- migration strategy unclear
- backup semantics unclear

Complex Sanads will worsen this dramatically.

---

# 10. CLI Audit

## 10.1 CLI Is Too Presentation-Oriented

The CLI emphasizes:

- pretty output
- chain discovery
- templates
- rendering

instead of:

- deterministic machine interfaces
- canonical export formats
- verification pipelines
- schema tooling
- proof introspection

The CLI should become a protocol engineering tool.

Not merely a user utility.

---

## 10.2 Chain Config Validation Is Weak

Validation checks mostly:

- empty strings
- presence of endpoints

This is not serious validation.

You need:

- schema validation
- capability validation
- finality model validation
- deployment consistency validation
- chain compatibility validation
- protocol compatibility validation

---

# 11. Testing Audit

## 11.1 Current Testing Is Insufficient for Protocol Freezing

You have:

- fuzzing
- compile-fail
- property tests
- golden tests

But missing:

- adversarial distributed tests
- Byzantine RPC simulations
- multi-chain rollback simulations
- serialization differential testing
- independent implementation compatibility testing
- deterministic replay testing across versions
- proof mutation corpus testing
- malformed schema corpus testing
- resource exhaustion fuzzing
- contract equivalence testing across chains

---

## 11.2 No Formal Verification Layer

Given the protocol ambitions:

- formal state invariants
- model checking
- TLA+
- Alloy
- K-framework
- symbolic execution

should already exist.

Especially before freezing contracts and runtime.

---

# 12. Dependency Audit

## 12.1 Dependency Boundaries Are Weak

Core appears to depend conceptually on runtime concerns.

Runtime appears to understand protocol semantics.

Wallet appears to understand proof semantics.

Explorer appears to understand verification semantics.

This is impurity.

---

## 12.2 Missing Strict Layering

Required layering should be:

```text
core
  ↓
verification
  ↓
adapters
  ↓
runtime
  ↓
sdk
  ↓
applications
```

No upward semantic leakage.

Currently leakage exists everywhere.

---

# 13. Immediate Refactoring Recommendations Before Freezing Core

## 13.1 DO NOT Freeze Yet

Current architecture is not stable enough for a long-term frozen core/runtime.

Freezing now will permanently preserve:

- semantic drift
- weak canonicalization
- unclear proof semantics
- adapter impurity
- verification fragmentation
- runtime overreach

---

## 13.2 Extract Canonical Protocol Kernel

Create:

```text
csv-protocol
```

ONLY containing:

- canonical serialization
- hash registry
- proof taxonomy
- state transitions
- replay invariants
- protocol constants
- versioning
- schema semantics
- canonical verification

Nothing else.

---

## 13.3 Build Formal Content Model Before Complex Sanads

Before supporting complex content:

You need:

```text
ContentDescriptor
SchemaRegistry
MerkleizedContent
CanonicalEncoding
SelectiveDisclosure
AttachmentModel
EncryptionEnvelope
```

Without this, complex Sanads become unverifiable long-term.

---

## 13.4 Freeze Hashing and Serialization FIRST

Before any ecosystem adoption:

freeze:

- encoding
- hashing
- field ordering
- domain separation
- protocol versioning
- proof formats
- content addressing

Everything else can evolve.

These cannot.

---

## 13.5 Make Contracts Dumb and Stable

Contracts should become:

- minimal
- deterministic
- immutable
- event-oriented
- semantically frozen

Do not place evolving logic on-chain.

But do place enough canonical anchors to avoid trusted off-chain interpretation.

---

## 13.6 Create One Canonical Verifier

Mandatory.

Every ecosystem implementation must produce identical verification results.

---

## 13.7 Define Protocol Governance Before Ecosystem Expansion

You currently lack:

- protocol extension governance
- schema governance
- hash namespace governance
- chain capability governance
- proof type governance
- version negotiation
- deprecation rules

Without governance the protocol will fork socially.

---

# 14. Final Verdict

The repository is ambitious but not protocol-stable.

Main dangers:

1. Semantic drift.
2. Fragmented verification.
3. Weak canonicalization.
4. Adapter impurity.
5. Runtime overreach.
6. Undefined distributed consistency semantics.
7. Insufficient formalization.
8. Weak contract immutability planning.
9. Incomplete replay/finality semantics.
10. Unsafe future support for complex Sanads.

The most dangerous mistake now would be freezing core/runtime before:

- canonical serialization
- proof taxonomy
- verification centralization
- formal invariants
- content model formalization
- finality semantics
- replay semantics
- contract ABI constitution

are completely stabilized.

If ecosystem integrations start before these are fixed, you will accumulate permanent compatibility debt that cannot be repaired later without chain-wide migration.

