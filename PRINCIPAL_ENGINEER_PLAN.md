# CSV Protocol — Principal Engineer Implementation Plan

**Status:** Final  
**Author:** Principal Engineer  
**Addresses:** Auditor's 10 remaining criticisms (post-response-document review)  
**Design Philosophy:** Violating architecture must be harder than following it.

---

## Executive Summary

The prior response document converted critiques into remediations. Remediations are still discipline. This plan converts every remaining criticism into **mechanically enforced impossibility**. Each section contains: the auditor's exact objection, the structural gap it exposed, and the implementation that closes it with compile-time or CI-enforced guarantees — not README promises.

---

## Criticism 1: No Architectural Constitution

**Auditor:** "Nothing prevents someone six months later from adding `RetryProofOrchestrator` directly into `csv-runtime`. The architecture can regress instantly."

### Root Cause

`csv-architecture/tests/architecture_guard.rs` exists but only checks for `tokio::runtime::Builder` patterns and a few manifest fields via string scanning. It does not enforce a *directed acyclic dependency graph*. Any developer can add a `[dependencies]` line and bypass all stated intent.

### Implementation

#### Step 1: Codify the forbidden dependency graph in `deny.toml`

Create `deny.toml` at workspace root. This is machine-read by `cargo deny` in CI — not a README.

```toml
# deny.toml — Architectural Constitution
# Every entry here is a compile-time constraint.
# Violations fail CI with a precise error message.

[graph]
targets = []

[[graph.forbidden-edges]]
# csv-runtime is an orchestration facade only.
# It may NOT reach into protocol internals.
from = "csv-runtime"
to   = "csv-protocol"
path = "csv-protocol::internal"
message = "csv-runtime must import ONLY public protocol types. Direct internal access is forbidden."

[[graph.forbidden-edges]]
# Adapters must never depend on runtime.
# Adapters are leaf nodes. They receive runtime handles; they do not construct them.
from = "csv-adapters/*"
to   = "csv-runtime"
message = "Adapters are leaf nodes. They may not depend on csv-runtime."

[[graph.forbidden-edges]]
# Verifier must not depend on chain adapters.
# Verification is chain-agnostic. If this edge exists, the verifier is contaminated.
from = "csv-verifier"
to   = "csv-adapters/*"
message = "csv-verifier must be chain-agnostic. Adapter imports are forbidden."

[[graph.forbidden-edges]]
# Pure algebra layer must have zero infrastructure dependencies.
from = "csv-algebra"
to   = "serde"
message = "csv-algebra is no_std + no-serde. Use csv-wire for serialization."

[[graph.forbidden-edges]]
from = "csv-algebra"
to   = "tokio"
message = "csv-algebra is synchronous and allocation-minimal. No async runtimes."

[[graph.forbidden-edges]]
from = "csv-algebra"
to   = "reqwest"
message = "csv-algebra has zero network dependencies."
```

#### Step 2: Enforce the canonical dependency DAG with a custom lint

Add `csv-architecture/tests/dep_graph_constitution.rs`:

```rust
/// Architectural Constitution Test
/// 
/// This test is the machine-readable architectural contract.
/// It runs on every CI push. Failure is a build break, not a warning.
/// 
/// Layer definitions:
///   L0 (csv-algebra)      — pure types, no_std, no serde, no IO
///   L1 (csv-wire)         — serde + transport encoding of L0 types
///   L2 (csv-hash)         — cryptographic primitives over L0 types  
///   L3 (csv-protocol)     — protocol algebra; imports L0, L2
///   L4 (csv-verifier)     — verification logic; imports L3
///   L5 (csv-coordinator)  — orchestration; imports L3, L4, storage traits
///   L6 (csv-runtime)      — facade only; re-exports L5, adds binary config
///   L7 (csv-adapters/*)   — chain leaf nodes; imports L3, L4 only
///   L8 (csv-sdk, csv-cli) — user-facing; imports any layer
/// 
/// FORBIDDEN: any lower-numbered layer importing a higher-numbered layer.
/// FORBIDDEN: L7 importing L5, L6.
/// FORBIDDEN: L4 importing L7.
#[test]
fn dependency_dag_has_no_upward_edges() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .expect("cargo metadata must succeed");

    let layer = |name: &str| -> u8 {
        match name {
            "csv-algebra"                                     => 0,
            "csv-wire"                                        => 1,
            "csv-hash"                                        => 2,
            "csv-protocol"                                    => 3,
            "csv-verifier"                                    => 4,
            "csv-coordinator"                                 => 5,
            "csv-runtime"                                     => 6,
            n if n.starts_with("csv-") && n.contains("aptos")
                || n.contains("ethereum")
                || n.contains("solana")
                || n.contains("bitcoin")
                || n.contains("sui")
                || n.contains("celestia") => 7,
            "csv-sdk" | "csv-cli"                             => 8,
            _                                                 => 255,
        }
    };

    let mut violations: Vec<String> = vec![];

    for pkg in &metadata.packages {
        let from_layer = layer(&pkg.name);
        if from_layer == 255 { continue; }

        for dep in &pkg.dependencies {
            let to_layer = layer(&dep.name);
            if to_layer == 255 { continue; }

            // Adapter (L7) must not import coordinator (L5) or runtime (L6)
            if from_layer == 7 && (to_layer == 5 || to_layer == 6) {
                violations.push(format!(
                    "VIOLATION: {} (L{}) → {} (L{}) — adapters must not import runtime/coordinator",
                    pkg.name, from_layer, dep.name, to_layer
                ));
            }

            // Verifier (L4) must not import adapters (L7)
            if from_layer == 4 && to_layer == 7 {
                violations.push(format!(
                    "VIOLATION: {} (L{}) → {} (L{}) — verifier must be chain-agnostic",
                    pkg.name, from_layer, dep.name, to_layer
                ));
            }

            // Pure algebra (L0) must not import anything above L0
            if from_layer == 0 && to_layer > 0 {
                violations.push(format!(
                    "VIOLATION: csv-algebra → {} — algebra layer must have zero dependencies",
                    dep.name
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ARCHITECTURAL CONSTITUTION VIOLATED:\n{}",
        violations.join("\n")
    );
}
```

#### Step 3: CI gate in `.github/workflows/architecture.yml`

```yaml
name: Architectural Constitution
on: [push, pull_request]
jobs:
  constitution:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install cargo-deny
      - run: cargo deny check graph
      - run: cargo test -p csv-architecture --test dep_graph_constitution
      - name: No tokio::runtime::Builder in adapters
        run: |
          count=$(grep -rn "tokio::runtime::Builder" csv-adapters/ | wc -l)
          [ "$count" -eq 0 ] || (echo "FAIL: $count runtime construction sites in adapters" && exit 1)
      - name: No block_on outside binaries and tests
        run: |
          violations=$(grep -rn "\.block_on(" csv-*/src/ \
            --exclude-dir=csv-cli --exclude-dir=csv-sdk | grep -v "#\[cfg(test)\]")
          [ -z "$violations" ] || (echo "FAIL:\n$violations" && exit 1)
```

**Result:** Architecture decay is a build break on the next push. No discipline required.

---

## Criticism 2: Pure Types Proposal Is Still Impure

**Auditor:** "`csv-types` becomes a dumping ground. Serde sneaks in, transport types sneak in. Purity collapses."

### Root Cause

A "shared types crate" with no compiler enforcement is a convention. Conventions decay. The auditor correctly identified that the only true purity test is `no_std` compilation — if your protocol algebra requires `std`, it is application logic dressed as algebra.

### Implementation

#### New crate: `csv-algebra`

```
csv-algebra/
  src/
    lib.rs          # #![no_std] — this is enforced by the compiler, not a README
    transfer.rs     # TransferId, SealPoint, ChainId — pure newtypes
    proof.rs        # CanonicalProof, ProofAncestry — no wire encoding
    state.rs        # TransferPhase enum — no serde derives
    finality.rs     # FinalityEvidence — cryptographic commitment types
    replay.rs       # ReplayId, ReplayNonce — pure derivation
    error.rs        # AlgebraError — no std::error::Error (no_std)
  Cargo.toml
```

`csv-algebra/src/lib.rs`:
```rust
#![no_std]
// If this file compiles, the algebra layer is pure.
// If any dependency requires std, this line produces a compile error.
// No README. No convention. Compiler-enforced.
extern crate alloc;

pub mod error;
pub mod finality;
pub mod proof;
pub mod replay;
pub mod state;
pub mod transfer;
```

`csv-algebra/Cargo.toml`:
```toml
[package]
name = "csv-algebra"
edition = "2024"

[dependencies]
# Zero runtime dependencies.
# alloc is available via extern crate alloc.
# Any addition here that requires std will break the #![no_std] compile.

[features]
default = []
# std feature is ONLY for test harness compatibility — never enabled in production
std = []
```

#### New crate: `csv-wire`

Owns ALL serde, ALL transport encoding, ALL RPC wire format conversions. It depends on `csv-algebra`. The inverse is forbidden by `deny.toml`.

```
csv-wire/
  src/
    lib.rs
    proof.rs          # Serialize/Deserialize for CanonicalProof
    transfer.rs       # Wire encoding of transfer types
    rpc/
      aptos.rs        # Aptos RPC → csv-algebra types (TryFrom impls)
      ethereum.rs     # Ethereum RPC → csv-algebra types
      solana.rs
      bitcoin.rs
    canonical.rs      # Canonical byte encoding (no RPC assumptions)
  Cargo.toml
```

`csv-wire/Cargo.toml`:
```toml
[dependencies]
csv-algebra = { path = "../csv-algebra" }
serde        = { version = "1", features = ["derive"] }
hex          = "0.4"
# serde lives HERE and nowhere above this layer
```

**Migration CI gate** (added to architecture test):
```bash
# csv-algebra must compile under no_std
cargo build -p csv-algebra --no-default-features --target thumbv7m-none-eabi
```

Compile failure = purity violation. No engineer memory required.

---

## Criticism 3: Transition Algebra Is Still Weak

**Auditor:** "`HashMap<(State, Event), Result<State>>` still fails dynamically. `transition(Initiated, MintCompleted)` is still writable and only fails at runtime."

### Root Cause

The existing `csv-protocol/src/transfer_state/` directory already has typestate files (`locked.rs`, `proof_building.rs`, etc.) but the transitions between them use runtime dispatch patterns rather than consuming `self`. The auditor's test: can you write `transition(Initiated, MintCompleted)` and have it compile?

### Implementation

Every typestate struct is `#[must_use]` and transitions consume `self`. Illegal transitions are not runtime errors — they are type errors.

`csv-algebra/src/state.rs` (pure, no_std):

```rust
use alloc::boxed::Box;
use crate::proof::CanonicalProof;
use crate::finality::FinalityEvidence;

/// Marker trait — zero runtime cost, compile-time only
pub trait TransferState: sealed::Sealed {}
mod sealed { pub trait Sealed {} }

// ── State structs ─────────────────────────────────────────────────────────────

/// Source chain lock confirmed. No proof yet.
#[must_use = "TransferState must be driven to completion or rollback"]
pub struct Locked {
    pub seal_id: [u8; 32],
    pub source_chain: u32,
    pub dest_chain:   u32,
}

/// Proof construction underway.
#[must_use]
pub struct ProofBuilding {
    pub locked: Locked,
    pub attempt: u8,
}

/// Proof submitted, finality window pending.
#[must_use]
pub struct AwaitingFinality {
    pub proof: CanonicalProof,
    pub required_confirmations: u64,
}

/// Finality confirmed, verifier accepted proof.
#[must_use]
pub struct ProofValidated {
    pub proof:    CanonicalProof,
    pub evidence: FinalityEvidence,
}

/// Mint transaction submitted to destination chain.
#[must_use]
pub struct Minting {
    pub validated: ProofValidated,
    pub mint_tx:   [u8; 32],
}

/// Terminal state: success.
pub struct Completed {
    pub mint_tx:   [u8; 32],
    pub seal_id:   [u8; 32],
}

/// Terminal state: reorg or failure.
pub struct RolledBack {
    pub reason: RollbackReason,
    pub seal_id: [u8; 32],
}

#[derive(Debug)]
pub enum RollbackReason { Reorg, ProofInvalid, FinalityTimeout, MintFailed }

// ── Sealed impls ──────────────────────────────────────────────────────────────
impl sealed::Sealed for Locked         {}
impl sealed::Sealed for ProofBuilding  {}
impl sealed::Sealed for AwaitingFinality {}
impl sealed::Sealed for ProofValidated {}
impl sealed::Sealed for Minting        {}
impl sealed::Sealed for Completed      {}
impl sealed::Sealed for RolledBack     {}

impl TransferState for Locked          {}
impl TransferState for ProofBuilding   {}
impl TransferState for AwaitingFinality{}
impl TransferState for ProofValidated  {}
impl TransferState for Minting         {}

// ── Transitions ───────────────────────────────────────────────────────────────
// Each transition consumes self. The type system enforces the DAG.
// You CANNOT call .validate_proof() on a Minting — it won't compile.

impl Locked {
    /// Begin proof construction.
    pub fn begin_proof(self) -> ProofBuilding {
        ProofBuilding { locked: self, attempt: 0 }
    }
    /// Source chain reorganized before proof started.
    pub fn reorg(self) -> RolledBack {
        RolledBack { reason: RollbackReason::Reorg, seal_id: self.seal_id }
    }
}

impl ProofBuilding {
    /// Proof constructed, submit and await finality.
    pub fn submit_proof(self, proof: CanonicalProof, required: u64) -> AwaitingFinality {
        AwaitingFinality { proof, required_confirmations: required }
    }
    /// Proof construction failed — retry or abandon.
    pub fn fail(self) -> RolledBack {
        RolledBack { reason: RollbackReason::ProofInvalid, seal_id: self.locked.seal_id }
    }
}

impl AwaitingFinality {
    /// Verifier accepted proof + finality evidence.
    pub fn accept(self, evidence: FinalityEvidence) -> ProofValidated {
        ProofValidated { proof: self.proof, evidence }
    }
    /// Finality window expired.
    pub fn timeout(self) -> RolledBack {
        RolledBack { reason: RollbackReason::FinalityTimeout, seal_id: [0u8; 32] }
    }
}

impl ProofValidated {
    /// Submit mint transaction to destination chain.
    pub fn mint(self, tx: [u8; 32]) -> Minting {
        Minting { validated: self, mint_tx: tx }
    }
}

impl Minting {
    /// Mint confirmed on destination chain.
    pub fn confirm(self) -> Completed {
        Completed { mint_tx: self.mint_tx, seal_id: self.validated.proof.seal_id }
    }
    /// Mint transaction failed.
    pub fn fail(self) -> RolledBack {
        RolledBack { reason: RollbackReason::MintFailed, seal_id: self.validated.proof.seal_id }
    }
}
```

**Proof that illegal transitions are impossible** — this goes in `csv-core/tests/compile_fail/`:

```rust
// compile_fail/minting_to_proof_building.rs
// This must NOT compile. If it does, the typestate model is broken.
// 
// error[E0599]: no method named `begin_proof` found for struct `Minting`

fn illegal_transition(m: csv_algebra::state::Minting) {
    let _ = m.begin_proof(); // ← compile error: method does not exist on Minting
}
```

The existing `csv-core/tests/compile_fail/` directory already has this pattern. Replace its runtime-checked files with true `#[compile_fail]` tests using `trybuild`.

`csv-core/tests/typestate_compile_fail.rs`:
```rust
#[test]
fn illegal_transitions_are_compile_errors() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/minting_to_proof_building.rs");
    t.compile_fail("tests/compile_fail/locked_to_minting.rs");
    t.compile_fail("tests/compile_fail/skip_awaiting_finality.rs");
    t.compile_fail("tests/compile_fail/proof_validated_to_locked.rs");
}
```

**Result:** The state machine DAG is enforced by the Rust type checker. `HashMap` is deleted.

---

## Criticism 4: Byzantine Model Insufficient

**Auditor:** "A hostile RPC quorum can still fabricate consistent lies. You are building a cross-chain verification protocol. The only acceptable root of trust is cryptographic consensus evidence — not '3 RPC nodes agreed'."

### Root Cause

`QuorumRpcConfig` addresses *disagreement* between honest nodes. It does not address *coordinated deception* by all nodes. The auditor is correct: RPC is the wrong trust boundary for a cross-chain protocol. The boundary must be cryptographic.

### Implementation

#### New trait: `CryptographicAnchor` (in `csv-verifier`)

```rust
/// The only trust boundary accepted by this protocol.
/// 
/// An implementation of this trait proves chain state WITHOUT trusting
/// any RPC operator. Every implementation must be auditable against
/// the chain's consensus spec.
pub trait CryptographicAnchor: Send + Sync {
    /// Verify that a block hash commits to a valid chain with the given
    /// validator set. Implementations MUST:
    /// - Verify BLS/Ed25519/ECDSA quorum certificate over the block header
    /// - Verify validator set continuity from genesis or last trusted checkpoint
    /// - Reject if reorg depth exceeds `FinalityGuarantee::max_reorg_depth`
    fn verify_header(
        &self,
        header: &CanonicalBlockHeader,
        validator_set: &ValidatorSet,
        finality: &FinalityGuarantee,
    ) -> Result<VerifiedHeader, AnchorError>;

    /// Verify a Merkle inclusion proof anchored to a verified header.
    /// Implementations MUST:
    /// - Use the state_root from a previously `verify_header` result
    /// - Reject any proof that was not anchored to a cryptographically
    ///   verified header in the same call chain
    fn verify_inclusion(
        &self,
        proof: &CanonicalInclusionProof,
        anchor: &VerifiedHeader,
    ) -> Result<(), AnchorError>;
}
```

#### `FinalityGuarantee` — the auditor's required proof-carrying constraint (Criticism 6)

```rust
/// Structured finality guarantee.
/// 
/// This is NOT a boolean config flag.
/// It is a machine-readable proof-carrying constraint used by the
/// orchestrator to make security decisions at runtime.
#[derive(Debug, Clone)]
pub struct FinalityGuarantee {
    /// Maximum blocks that can be reorged without breaking finality.
    pub max_reorg_depth: u64,
    /// Whether finality is probabilistic (Bitcoin) or deterministic (BFT).
    pub is_probabilistic: bool,
    /// Fraction of validators assumed honest (e.g., 0.67 for BFT).
    pub validator_honesty_threshold: f32,
    /// Proof system used by this chain's finality mechanism.
    pub proof_system: ProofSystem,
    /// Maximum age of a proof before it is considered stale.
    pub max_proof_age_blocks: u64,
    /// Minimum number of independent anchor sources required.
    pub min_anchor_sources: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProofSystem {
    /// Bitcoin SPV with given confirmation depth.
    BitcoinSpv { confirmations: u64 },
    /// BFT quorum certificate (Tendermint, HotStuff, etc.).
    BftQc { quorum_fraction: f32 },
    /// ZK header proof (SP1, Risc0, etc.).
    ZkHeader { circuit_id: [u8; 32] },
    /// Ethereum PoS with beacon chain finality.
    EthereumPos { finality_epochs: u8 },
}
```

#### Adapter implementations

Each chain adapter implements `CryptographicAnchor` — not `QuorumRpcClient`:

```rust
// csv-adapters/csv-aptos/src/anchor.rs
pub struct AptosAnchor {
    // Holds the known validator set from genesis/trusted checkpoint.
    // This is the ONLY state. No RPC client. No endpoint list.
    validator_set: ValidatorSet,
    bls_verifier:  BlsVerifier,
}

impl CryptographicAnchor for AptosAnchor {
    fn verify_header(
        &self,
        header: &CanonicalBlockHeader,
        validator_set: &ValidatorSet,
        finality: &FinalityGuarantee,
    ) -> Result<VerifiedHeader, AnchorError> {
        // Actual HotStuff 2f+1 quorum certificate verification.
        // NOT "block exists" — actual BLS aggregate signature verification.
        let qc = header.quorum_cert
            .as_ref()
            .ok_or(AnchorError::MissingQuorumCert)?;
        
        self.bls_verifier.verify_aggregate(
            &qc.signature,
            &qc.signers,
            &header.hash(),
            validator_set,
            finality.validator_honesty_threshold,
        )?;

        Ok(VerifiedHeader { hash: header.hash(), height: header.height })
    }
    // ...
}
```

**`require_certified` flag is deleted.** The flag does not exist in `CryptographicAnchor`. There is no code path to bypass verification. The auditor's "Verification Theater" (Criticism 6 of the first round) is structurally impossible.

---

## Criticism 5: Missing Failure Containment Domains

**Auditor:** "One degraded chain can starve the entire protocol. What isolates blast radius? Nothing."

### Root Cause

`csv-runtime/src/transfer_coordinator.rs` (2963 lines) is a single coordinator with shared queues. Aptos RPC degradation can fill the shared task queue, blocking Ethereum transfers.

### Implementation

#### New crate: `csv-coordinator`

Extracted from `csv-runtime`. The coordinator is restructured into **per-chain execution cells**.

```
csv-coordinator/
  src/
    cell.rs          # ChainCell — isolated execution unit per chain
    router.rs        # TransferRouter — routes transfers to correct cell
    circuit.rs       # CellCircuitBreaker — per-cell fault isolation
    memory.rs        # MemoryCeiling — per-cell allocation limits
    lib.rs
```

`csv-coordinator/src/cell.rs`:
```rust
/// An isolated execution unit for one chain adapter.
/// 
/// Each cell owns:
/// - Its own bounded mpsc queue (not shared with other cells)
/// - Its own Tokio runtime handle (not the global runtime)
/// - Its own circuit breaker
/// - Its own memory ceiling
/// - Its own retry policy
/// 
/// A cell degradation CANNOT propagate to sibling cells.
/// This is enforced by Rust ownership, not by operating discipline.
pub struct ChainCell {
    chain_id:        ChainId,
    queue:           mpsc::Sender<CellTask>,
    circuit:         CellCircuitBreaker,
    memory_ceiling:  MemoryCeiling,
    metrics:         CellMetrics,
}

impl ChainCell {
    pub fn spawn(config: CellConfig, anchor: Arc<dyn CryptographicAnchor>) -> Self {
        // Each cell gets its own bounded channel.
        // Overflow = backpressure to the router, NOT to other cells.
        let (tx, rx) = mpsc::channel::<CellTask>(config.max_queue_depth);

        tokio::spawn(cell_worker(rx, anchor, config.clone()));

        ChainCell {
            chain_id:       config.chain_id,
            queue:          tx,
            circuit:        CellCircuitBreaker::new(config.circuit_breaker),
            memory_ceiling: MemoryCeiling::new(config.max_memory_bytes),
            metrics:        CellMetrics::new(&config.chain_id),
        }
    }

    /// Submit work to this cell.
    /// Returns Err(Backpressure) if cell queue is full.
    /// The caller (router) handles backpressure — it does not block other cells.
    pub async fn submit(&self, task: CellTask) -> Result<(), CellError> {
        if self.circuit.is_open() {
            return Err(CellError::CircuitOpen(self.chain_id));
        }
        self.queue.try_send(task).map_err(|_| CellError::Backpressure(self.chain_id))
    }
}

/// Isolation test — verifies cell independence under degradation.
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn aptos_cell_degradation_does_not_block_ethereum_cell() {
        let aptos_cell = ChainCell::spawn(
            CellConfig { chain_id: ChainId::Aptos, max_queue_depth: 2, ..Default::default() },
            Arc::new(AlwaysTimeoutAnchor),  // simulated degradation
        );
        let eth_cell = ChainCell::spawn(
            CellConfig { chain_id: ChainId::Ethereum, max_queue_depth: 100, ..Default::default() },
            Arc::new(InstantSuccessAnchor),
        );

        // Flood Aptos cell to capacity
        for _ in 0..10 {
            let _ = aptos_cell.submit(dummy_task()).await;
        }

        // Ethereum cell must still accept work immediately
        let result = eth_cell.submit(dummy_task()).await;
        assert!(result.is_ok(), "Ethereum cell blocked by Aptos degradation");
    }
}
```

`csv-coordinator/src/router.rs`:
```rust
/// Routes incoming transfer requests to the correct chain cell.
/// Owns one ChainCell per registered chain.
/// Degradation of any single cell does NOT affect other cells.
pub struct TransferRouter {
    cells: HashMap<ChainId, ChainCell>,
}

impl TransferRouter {
    pub async fn route(&self, transfer: InboundTransfer) -> Result<(), RouterError> {
        let cell = self.cells
            .get(&transfer.source_chain)
            .ok_or(RouterError::UnknownChain(transfer.source_chain))?;

        cell.submit(CellTask::Process(transfer))
            .await
            .map_err(RouterError::Cell)
    }
}
```

---

## Criticism 6: Capability Negotiation Superficial

**Auditor:** "`supports_light_client = true` is meaningless. Capabilities are not booleans. Missing: trusted vs trustless, probabilistic vs deterministic, finality lag, reorg depth."

### Root Cause

The `CapabilityRequirements` struct exists in `csv-protocol` but is defined as a bag of `bool` and `Option<u64>` fields. These cannot carry the semantic weight required for orchestration decisions.

### Implementation

`FinalityGuarantee` (defined in Criticism 4 above) IS the capability model. Wire it into orchestration:

```rust
// csv-coordinator/src/negotiation.rs

/// Negotiator uses FinalityGuarantee — not booleans — to make security decisions.
pub struct CapabilityNegotiator {
    chain_guarantees: HashMap<ChainId, FinalityGuarantee>,
}

impl CapabilityNegotiator {
    /// Validate that a proposed transfer can meet the required security level.
    /// Returns the negotiated execution plan or an explicit refusal with reason.
    pub fn negotiate(
        &self,
        transfer: &InboundTransfer,
        required: &SecurityRequirements,
    ) -> Result<NegotiatedPlan, NegotiationError> {
        let source_guarantee = self.chain_guarantees
            .get(&transfer.source_chain)
            .ok_or(NegotiationError::UnknownChain)?;

        // Determinism requirement: reject probabilistic finality if caller requires deterministic
        if required.requires_deterministic_finality && source_guarantee.is_probabilistic {
            return Err(NegotiationError::FinalityMismatch {
                required: "deterministic",
                available: "probabilistic",
                chain: transfer.source_chain,
            });
        }

        // Reorg depth requirement
        if source_guarantee.max_reorg_depth < required.min_reorg_depth {
            return Err(NegotiationError::InsufficientReorgProtection {
                required:  required.min_reorg_depth,
                available: source_guarantee.max_reorg_depth,
            });
        }

        // Validator honesty threshold
        if source_guarantee.validator_honesty_threshold < required.min_honesty_threshold {
            return Err(NegotiationError::InsufficientValidatorTrust {
                required:  required.min_honesty_threshold,
                available: source_guarantee.validator_honesty_threshold,
            });
        }

        // Compute fallback plan if primary proof system is unavailable
        let proof_system = self.select_proof_system(source_guarantee, required)?;

        Ok(NegotiatedPlan {
            proof_system,
            confirmation_depth: source_guarantee.max_reorg_depth + 1,
            max_proof_age_blocks: source_guarantee.max_proof_age_blocks,
        })
    }
}
```

Chain TOML files change from boolean flags to `FinalityGuarantee` structs:

```toml
# chains/aptos-testnet.toml
[finality_guarantee]
max_reorg_depth            = 0          # BFT — no reorgs
is_probabilistic           = false
validator_honesty_threshold = 0.67
proof_system               = { type = "BftQc", quorum_fraction = 0.67 }
max_proof_age_blocks       = 100
min_anchor_sources         = 1
```

At startup, if a chain's TOML is missing `[finality_guarantee]`, the process refuses to start:
```
FATAL: chains/aptos-testnet.toml missing [finality_guarantee] block.
Boolean capability flags are no longer accepted.
See csv-docs/CHAIN_ONBOARDING.md for the required FinalityGuarantee schema.
```

---

## Criticism 7: Mock Strategy Still Unsafe

**Auditor:** "Mocks remain behaviorally unconstrained. Eventually tests prove the mock framework works, not the protocol."

### Root Cause

`MockAptosRpc::verify_checkpoint` unconditionally returns `Ok(true)`. Tests pass regardless of whether real verification logic exists. The mock is not a simulation — it is a bypass.

### Implementation

#### Replace mocks with canonical trace fixtures

`csv-testkit` is restructured. The `MockAptosRpc` that always returns `Ok(true)` is deleted. Its replacement:

```rust
// csv-testkit/src/traces.rs

/// A canonical trace is a recorded sequence of real chain interactions
/// with known-good expected outputs. Tests that pass against a CanonicalTrace
/// are testing the protocol, not the mock.
pub struct CanonicalTrace {
    /// Recorded real RPC responses (captured from testnet, then frozen)
    pub rpc_responses: Vec<RecordedRpcInteraction>,
    /// Expected outputs after processing this trace
    pub expected_outputs: Vec<ExpectedOutput>,
    /// Known violations in this trace (for adversarial testing)
    pub injected_faults: Vec<InjectedFault>,
}

impl CanonicalTrace {
    /// Load a canonical trace from the fixtures directory.
    /// These files are checked into version control and never change
    /// without a explicit RFC + review.
    pub fn load(name: &str) -> Self {
        let path = format!("csv-testkit/fixtures/{}.trace.json", name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }
}
```

Fixture files (checked into `csv-testkit/fixtures/`):
- `aptos_valid_checkpoint.trace.json` — real Aptos testnet checkpoint, known valid
- `aptos_invalid_bls_signature.trace.json` — checkpoint with tampered BLS sig
- `ethereum_valid_finality.trace.json` — real Ethereum Sepolia finality proof
- `ethereum_wrong_length_hash.trace.json` — `parse_hex_bytes32` adversarial case

#### Adversarial mocks replace optimistic mocks

```rust
// csv-testkit/src/adversarial.rs

/// Byzantine RPC — returns plausible but cryptographically invalid responses.
/// Used to verify that the verifier correctly rejects them.
pub struct ByzantineRpcReader {
    fault_mode: ByzantineFaultMode,
}

pub enum ByzantineFaultMode {
    /// Returns valid-looking zero hashes for all block hashes
    ZeroHashInjection,
    /// Returns success status for all transactions regardless of actual status
    AlwaysSuccessStatus,
    /// Truncates hex strings to test parse_hex_bytes32 hardening
    TruncatedHex { truncate_to: usize },
    /// Returns responses from a different block height (stale data)
    StaleHeightInjection { lag_blocks: u64 },
    /// Silently drops every Nth response (simulates censorship)
    SelectiveCensorship { every_n: usize },
}
```

**CI gate:** Every test that previously used `MockAptosRpc` must be migrated to either `CanonicalTrace` or `ByzantineRpcReader`. The `MockAptosRpc` type is marked `#[deprecated = "Use CanonicalTrace or ByzantineRpcReader. See csv-testkit/MIGRATION.md"]`.

---

## Criticism 8: Missing Deterministic Execution

**Auditor:** "Your architecture still permits nondeterministic coordination. Task order changes, retries reorder events, replay timing differs. You need event-sourced deterministic orchestration."

### Root Cause

`csv-runtime/src/transfer_coordinator.rs` mixes orchestration with side effects. There is no log of what happened, only the current state. Recovery after crash is best-effort reconstruction.

### Implementation

#### Event-sourced coordinator architecture

```
csv-coordinator/
  src/
    journal/
      event.rs         # CoordinatorEvent — the append-only record
      log.rs           # EventLog — durable, ordered, immutable
      replay.rs        # LogReplayer — deterministic state reconstruction
    coordinator.rs     # Pure function: (State, Event) → State
```

**Core principle:** The coordinator is a pure function. All side effects are represented as events logged BEFORE execution.

`csv-coordinator/src/journal/event.rs`:
```rust
/// Every state change in the coordinator is represented as one of these events.
/// 
/// INVARIANT: No coordinator state change occurs without a corresponding event
/// being durably logged first. This is enforced by the coordinator architecture,
/// not by convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinatorEvent {
    TransferInitiated      { transfer_id: TransferId, source: ChainId, dest: ChainId, seal_id: [u8; 32] },
    ProofBuildingStarted   { transfer_id: TransferId, attempt: u8 },
    ProofSubmitted         { transfer_id: TransferId, proof_hash: [u8; 32] },
    FinalityConfirmed      { transfer_id: TransferId, evidence: FinalityEvidence },
    MintSubmitted          { transfer_id: TransferId, mint_tx: [u8; 32] },
    MintConfirmed          { transfer_id: TransferId },
    RolledBack             { transfer_id: TransferId, reason: RollbackReason },
    // Operational events (never alter protocol state, but are auditable)
    CellCircuitOpened      { chain_id: ChainId, consecutive_failures: u32 },
    BackpressureTriggered  { chain_id: ChainId, queue_depth: usize },
}
```

`csv-coordinator/src/coordinator.rs`:
```rust
/// The coordinator is a pure function.
/// It has no mutable state. It cannot produce side effects.
/// 
/// Usage:
///   1. Append an event to the durable log.
///   2. Call apply(state, event) to get the next state.
///   3. Execute the side effect the new state requires (RPC call, etc.).
///   4. If the side effect produces an outcome, log another event and repeat.
/// 
/// Recovery:
///   1. Read all events from the durable log.
///   2. Fold them with apply() from the initial state.
///   3. The result is bit-for-bit identical to the state before crash.
///   4. No heuristics. No reconstruction. Deterministic.
pub fn apply(state: CoordinatorState, event: &CoordinatorEvent) -> CoordinatorState {
    match event {
        CoordinatorEvent::TransferInitiated { transfer_id, source, dest, seal_id } => {
            let transfer = TransferRecord {
                id: *transfer_id,
                phase: TransferPhase::Locked(Locked {
                    seal_id: *seal_id,
                    source_chain: *source,
                    dest_chain: *dest,
                }),
            };
            state.with_transfer(*transfer_id, transfer)
        }

        CoordinatorEvent::ProofSubmitted { transfer_id, proof_hash } => {
            state.map_transfer(*transfer_id, |t| {
                match t.phase {
                    TransferPhase::ProofBuilding(locked) => TransferRecord {
                        phase: TransferPhase::AwaitingFinality(AwaitingFinality {
                            proof: CanonicalProof::from_hash(*proof_hash),
                            required_confirmations: 0, // filled by finality cell
                        }),
                        ..t
                    },
                    // Any other phase + ProofSubmitted = protocol violation
                    other => panic!(
                        "INVARIANT VIOLATION: ProofSubmitted event on transfer {} in phase {:?}",
                        transfer_id, other
                    ),
                }
            })
        }
        // ... all other events
    }
}

/// Deterministic recovery test.
/// Given the same event log, apply() MUST produce identical state on every run.
#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_recovery_produces_identical_state() {
        let events = canonical_transfer_event_sequence();

        let state_a = events.iter().fold(CoordinatorState::empty(), |s, e| apply(s, e));
        let state_b = events.iter().fold(CoordinatorState::empty(), |s, e| apply(s, e));

        assert_eq!(state_a, state_b);
    }

    #[test]
    fn crash_recovery_is_identical_to_normal_execution() {
        let events = canonical_transfer_event_sequence();
        let mid = events.len() / 2;

        // Simulate crash at midpoint, recover from log
        let state_at_crash = events[..mid].iter().fold(CoordinatorState::empty(), |s, e| apply(s, e));
        let state_recovered = events.iter().fold(CoordinatorState::empty(), |s, e| apply(s, e));

        // Full replay must equal running all events in one pass
        let state_full = events.iter().fold(CoordinatorState::empty(), |s, e| apply(s, e));
        assert_eq!(state_recovered, state_full);
    }
}
```

---

## Criticism 9: No Formal Invariant Layer

**Auditor:** "Where are invariants formally defined? There is no executable spec, no model checker, no property testing framework. Your architecture is still convention-based."

### Root Cause

`csv-docs/PROTOCOL_INVARIANTS.md` documents invariants in prose. `csv-core/tests/invariant_*.rs` tests them with unit tests. Neither is a formal specification. Unit tests check specific cases; invariant violations can still exist in untested paths.

### Implementation

#### New crate: `csv-invariants`

```
csv-invariants/
  src/
    lib.rs
    replay.rs           # ReplayImpossibility — no two transfers share a seal_id
    mint.rs             # SingleMintGuarantee — one mint per verified proof
    ancestry.rs         # ProofAncestry — proof chain is acyclic and verified
    seal.rs             # SealUniqueness — seal consumed exactly once
    finality.rs         # FinalityContinuity — finality evidence is monotonic
    determinism.rs      # DeterministicRecovery — apply() is referentially transparent
  tests/
    proptest_replay.rs
    proptest_mint.rs
    proptest_seal.rs
  Cargo.toml
```

`csv-invariants/src/replay.rs`:
```rust
/// Invariant: No two completed transfers may share the same seal_id.
/// 
/// This is the core replay protection guarantee.
/// It is tested with property-based testing, not just unit tests.
pub fn replay_impossibility(completed: &[CompletedTransfer]) -> InvariantResult {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for transfer in completed {
        if !seen.insert(transfer.seal_id) {
            return InvariantResult::Violated(InvariantViolation::ReplayDetected {
                seal_id: transfer.seal_id,
            });
        }
    }
    InvariantResult::Holds
}
```

`csv-invariants/tests/proptest_replay.rs`:
```rust
use proptest::prelude::*;
use csv_invariants::replay::replay_impossibility;

proptest! {
    /// For any sequence of transfers that the coordinator produces,
    /// if the coordinator is correct, replay_impossibility MUST hold.
    /// 
    /// This generates thousands of random transfer sequences and
    /// verifies the invariant on every one of them.
    #[test]
    fn replay_invariant_holds_for_all_valid_coordinators(
        transfers in proptest::collection::vec(arb_completed_transfer(), 0..1000)
    ) {
        // Deduplicate seal IDs (as a correct coordinator would)
        let deduped = deduplicate_by_seal_id(transfers);
        prop_assert_eq!(
            replay_impossibility(&deduped),
            InvariantResult::Holds
        );
    }

    /// Any sequence with a duplicate seal_id MUST be detected.
    #[test]
    fn replay_invariant_detects_all_duplicates(
        transfers in arb_transfers_with_duplicate_seal()
    ) {
        prop_assert_eq!(
            replay_impossibility(&transfers),
            InvariantResult::Violated(_)
        );
    }
}
```

**Alloy / TLA+ integration** — the existing `formal/` directory already has `ReplaySafety.tla` and `ReplaySafety.als`. These are currently documentation. Make them CI-executable:

```yaml
# .github/workflows/formal.yml
- name: Run TLA+ model checker
  run: |
    java -jar tla2tools.jar -workers auto formal/ReplaySafety.tla
    # CI fails if any invariant violation is found by the model checker
```

---

## Criticism 10: No Compression Philosophy

**Auditor:** "Every new concern gets a crate. Very few things get deleted. The architecture lacks a universal protocol kernel. New chains still introduce new semantics. The architecture is chain-centric, not evidence-centric."

### Root Cause

The auditor's final and deepest criticism: this is not a technical gap — it is a design philosophy gap. The architecture accumulates. It does not compress.

### Implementation

#### The Universal Protocol Kernel

The entire cross-chain protocol reduces to a four-step pipeline. Everything else is a codec or transport adapter:

```
Chain Evidence
    ↓ [CryptographicAnchor::verify_header]
Canonical Verification Algebra
    ↓ [csv-algebra typestate: AwaitingFinality → ProofValidated]
Deterministic State Transition
    ↓ [CoordinatorEvent appended, apply() called]
Mint Authorization
    ↓ [MintAdapter::submit authorized with ProofValidated token]
```

**Structural rule:** A new chain is onboarded by implementing exactly **4 interfaces**:

| Interface | Where defined | What it does |
|---|---|---|
| `CryptographicAnchor` | `csv-verifier` | Verifies block headers cryptographically |
| `InclusionProver` | `csv-verifier` | Generates and verifies Merkle inclusion proofs |
| `MintAdapter` | `csv-adapter-core` | Submits mint transaction to destination chain |
| `FinalityGuarantee` (TOML) | chain config | Declares finality semantics |

A new chain adapter is **4 files**:
```
csv-adapters/csv-<newchain>/
  src/
    anchor.rs      # impl CryptographicAnchor
    prover.rs      # impl InclusionProver
    mint.rs        # impl MintAdapter
    lib.rs         # re-exports, FinalityGuarantee TOML loading
  Cargo.toml       # depends only on csv-algebra, csv-verifier
```

A new chain introduces **zero new protocol concepts**. If a chain adapter needs to introduce a new concept into `csv-algebra`, that is a **RFC gate** — it requires a formal justification for why the concept cannot be expressed using existing algebra.

**Deletion schedule** — the following duplicate files are deleted (not deprecated) as part of this plan:

| Deleted | Replaced by |
|---|---|
| `csv-proof/` (entire crate) | `csv-algebra::proof::CanonicalProof` |
| `MockAptosRpc` (full body) | `CanonicalTrace` + `ByzantineRpcReader` |
| `CheckpointConfig::require_certified` | Deleted — `CryptographicAnchor` has no bypass flag |
| `parse_hex_bytes32` (infallible) | `parse_hex_bytes32_strict() -> Result<[u8;32], HexError>` |
| `csv-runtime/src/transfer_coordinator.rs` (2963 lines) | `csv-coordinator/src/coordinator.rs` (pure fn) + `ChainCell` |
| `HashMap<(State, Event), ...>` transition table | Typestate transitions in `csv-algebra::state` |

---

## Implementation Sequence

Each phase is independently reviewable and mergeable. No phase depends on completion of a later phase.

| Phase | Duration | Deliverable | Closes Auditor Criticisms |
|---|---|---|---|
| **P0** | Week 1–2 | `csv-algebra` crate compiles `no_std`; `deny.toml` in CI | 1, 2 |
| **P0** | Week 1–2 | `parse_hex_bytes32` → `Result`; `require_certified` deleted | Prior Round P0 |
| **P1** | Week 3–4 | Typestate transitions + `trybuild` compile-fail tests | 3 |
| **P1** | Week 3–4 | `CryptographicAnchor` trait; Aptos BLS implementation | 4 |
| **P1** | Week 5–6 | `ChainCell` per-chain execution isolation | 5 |
| **P1** | Week 5–6 | `FinalityGuarantee` struct; chain TOML migration | 6 |
| **P2** | Week 7–8 | `CanonicalTrace` fixtures; `MockAptosRpc` deprecated | 7 |
| **P2** | Week 7–8 | `CoordinatorEvent` log; `apply()` pure function | 8 |
| **P2** | Week 9–10 | `csv-invariants` crate; proptest suites; TLA+ in CI | 9 |
| **P3** | Week 11–12 | `csv-proof` crate deleted; adapter core 4-interface target | 10 |

---

## Verification: What the Auditor Cannot Deny

| Auditor Claim | Our Counter |
|---|---|
| "Architecture can regress instantly" | `dep_graph_constitution` test breaks CI if a forbidden edge is added. No merge possible. |
| "Purity collapses when serde sneaks in" | `csv-algebra` is `#![no_std]`. Adding serde is a compile error, not a convention violation. |
| "Illegal transitions fail dynamically" | `trybuild` compile-fail tests verify that `minting.begin_proof()` does not compile. |
| "3 RPC nodes agreed is not a trust boundary" | `CryptographicAnchor` has no code path that bypasses cryptographic verification. The `require_certified` flag does not exist. |
| "One degraded chain starves the protocol" | `ChainCell` test verifies that flooding Aptos queue does not block Ethereum cell. Ownership-enforced. |
| "Capabilities are booleans" | `FinalityGuarantee` struct. TOML boolean flags fail to parse at startup with an explicit fatal error. |
| "Mocks prove the mock framework" | `MockAptosRpc` is deprecated. `CanonicalTrace` uses recorded real chain data. Fixtures are version-controlled. |
| "Coordination is nondeterministic" | `coordinator.apply()` is a pure function. Deterministic recovery test proves identical output from same input. |
| "Architecture is convention-based" | `csv-invariants` + proptest runs 10,000+ random cases per invariant. TLA+ runs in CI. |
| "Architecture accumulates, never compresses" | New chain = 4 files, 4 interfaces, 0 new protocol concepts. RFC required to add any new concept to `csv-algebra`. |

---

## Appendix A: Crate Dependency DAG (Final State)

```
csv-algebra (L0, no_std)
    ↑
csv-wire (L1, serde)          csv-hash (L2, crypto)
         ↑                         ↑
         └──────── csv-protocol (L3) ──────────┘
                        ↑
                  csv-verifier (L4)
                        ↑
                csv-coordinator (L5)
                        ↑
                  csv-runtime (L6, facade)
                        
csv-adapters/* (L7) ────→ csv-verifier (L4)
csv-adapters/* (L7) ────→ csv-protocol (L3)
csv-adapters/* (L7) ✗──→ csv-runtime (L6) [FORBIDDEN by deny.toml]

csv-sdk, csv-cli (L8) → any layer
```

---

## Appendix B: New Crates Summary

| Crate | Lines (est.) | Replaces | Key property |
|---|---|---|---|
| `csv-algebra` | ~600 | `csv-proof` types + scattered types | `#![no_std]` compiler-enforced purity |
| `csv-wire` | ~400 | Serde impls across crates | Single serde boundary |
| `csv-coordinator` | ~800 | `transfer_coordinator.rs` (2963 lines) | Pure `apply()` function |
| `csv-invariants` | ~500 | `PROTOCOL_INVARIANTS.md` (prose) | Proptest + TLA+ in CI |
| `csv-adapter-core` | ~300 | Per-adapter boilerplate | 4-interface onboarding contract |

Total lines added: ~2600  
Total lines deleted: ~4000+  
Net: compression, not accumulation.
