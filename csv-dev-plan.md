# CSV Protocol — Code-Level Development & Architecture Plan

> Target: pure, scalable, modular, elegant architecture as specified in `dep_graph_constitution.rs`
> Organized by workstream. Each task is atomic, reviewable, and unblocks the next.

---

## Architectural Constitution (Reference)

```
L0  csv-algebra      pure types, no_std, zero deps, zero serde
L1  csv-wire         ALL serde, ALL transport encoding of L0 types
L2  csv-hash         cryptographic primitives over L0 types
L3  csv-protocol     protocol algebra — imports L0, L2
L4  csv-verifier     verification logic — imports L3
L5  csv-coordinator  orchestration — imports L3, L4, storage traits
L6  csv-runtime      facade only — re-exports L5, binary config
L7  csv-adapters/*   chain leaf nodes — imports L3, L4 only
L8  csv-sdk, csv-cli user-facing — imports any layer
```

**Forbidden edges**: any lower layer importing a higher layer; L7→L5/L6; L4→L7.

---

## Workstream A — csv-wire Activation (Biggest Gap)

`csv-wire` is declared as the sole owner of ALL serde but nothing uses it.
Every crate from L2 up derives `Serialize/Deserialize` directly. This violates
the architectural constitution and makes wire-format changes cascade everywhere.

### A-1 — Audit current serde surface

Scan every `csv-protocol`, `csv-hash`, `csv-proof`, `csv-verifier`, and
`csv-codec` source file for `#[derive(Serialize, Deserialize)]`.
Produce a list grouped by type name. This list becomes the migration manifest.

```bash
grep -rn "#\[derive.*Serialize" csv-protocol/src csv-hash/src csv-proof/src \
  csv-verifier/src csv-codec/src \
  | grep -v "csv-wire" | sort > /tmp/serde_audit.txt
```

### A-2 — Define wire-boundary types in csv-wire

For each internal type that crosses a wire boundary, create a `*Wire` mirror
in `csv-wire`. Pattern already exists in `csv-wire/src/canonical.rs` for
`CanonicalProof` → `CanonicalProofWire`. Scale it to every type.

Priority order:
1. `csv_protocol::proof_types::ProofBundle` → `csv_wire::proof::ProofBundleWire` (**already started**)
2. `csv_protocol::seal::SealPoint` → `csv_wire::seal::SealPointWire`
3. `csv_protocol::transfer_state::{Locked, AwaitingFinality, ProofBuilding, ProofValidated}` → `csv_wire::transfer_state::*Wire`
4. `csv_hash::{Hash, ReplayIdHash, SanadId, Commitment}` → `csv_wire::primitives::*Wire`
5. RPC chain types in `csv-wire/src/rpc/{bitcoin,ethereum,solana,aptos}.rs` (module already exists, needs population)

Each `*Wire` type must:
- Derive `Serialize, Deserialize` (ONLY in csv-wire)
- Implement `From<Internal>` and `TryFrom<Wire> for Internal`
- Hex-encode all `[u8; N]` and `Vec<u8>` fields (pattern from `canonical.rs`)

```rust
// csv-wire/src/seal.rs — example
use csv_algebra::seal::SealPoint;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealPointWire {
    pub seal_bytes: String,   // hex
    pub output_index: Option<u32>,
}

impl From<SealPoint> for SealPointWire {
    fn from(s: SealPoint) -> Self {
        Self {
            seal_bytes: hex::encode(&s.seal_bytes),
            output_index: s.output_index,
        }
    }
}

impl TryFrom<SealPointWire> for SealPoint {
    type Error = String;
    fn try_from(w: SealPointWire) -> Result<Self, Self::Error> {
        Ok(SealPoint::new(
            hex::decode(&w.seal_bytes)
                .map_err(|e| format!("seal_bytes: {e}"))?,
            w.output_index,
        ).map_err(|e| e.to_string())?)
    }
}
```

### A-3 — Strip serde from L0–L4 internal types

After `*Wire` mirrors exist, remove `Serialize, Deserialize` from all internal
types. Use `#[cfg_attr(feature = "serde", derive(...))]` as a transitional gate
if some tests still need direct serialization — but the final target is zero
serde derives on L0–L4 types.

**Cargo.toml changes** — remove serde from direct deps:
```toml
# csv-protocol/Cargo.toml — REMOVE
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```
Re-add only if a specific module genuinely serializes to storage (not wire),
and document why in a comment.

### A-4 — Wire chain-adapter RPCs through csv-wire

Each adapter (`csv-bitcoin`, `csv-ethereum`, etc.) currently serializes its own
RPC responses. Route these through the pre-existing `csv_wire::rpc::*` modules.

For Bitcoin:
```rust
// csv-wire/src/rpc/bitcoin.rs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BitcoinTxWire {
    pub txid: String,
    pub confirmations: u32,
    pub block_hash: Option<String>,
    pub value_sats: u64,
}
// adapter calls: BitcoinTxWire → csv_algebra types
```

Same pattern for Ethereum (`eth_getTransactionReceipt`), Solana, Aptos.

### A-5 — Enforce via deny.toml

Add a `cargo-deny` rule that forbids `serde` as a direct dependency for L0–L4:

```toml
# deny.toml — add to [bans] section
[[bans.deny]]
name = "serde"
wrappers = ["csv-wire", "csv-sdk", "csv-cli", "csv-runtime", "csv-testkit"]
# Any crate NOT in wrappers that lists serde gets a build error
```

And add `csv-wire` usage check to `csv-architecture/tests/architecture_guard.rs`:
```rust
#[test]
fn l1_to_l4_crates_do_not_directly_import_serde() {
    let forbidden = ["csv-protocol", "csv-hash", "csv-proof", "csv-verifier", "csv-codec"];
    for crate_name in forbidden {
        let manifest = fs::read_to_string(
            workspace_root().join(format!("{crate_name}/Cargo.toml"))
        ).unwrap();
        assert!(
            !manifest.contains(r#"serde = "#) || manifest.contains("# allowed:"),
            "{crate_name} has a direct serde dep — route through csv-wire"
        );
    }
}
```

---

## Workstream B — csv-core Elimination

`csv-core/README.md` self-declares: *"Legacy crate — migration in progress."*
Three crates still import it: `csv-sdk`, and indirectly through transitives.

### B-1 — Map remaining csv-core modules to target crates

| csv-core module          | Target crate                     | Notes                                        |
|--------------------------|----------------------------------|----------------------------------------------|
| `client`                 | `csv-sdk/src/client.rs`          | SDK boundary, not protocol                   |
| `consignment`            | `csv-wire/src/consignment.rs`    | Wire format — belongs in csv-wire            |
| `transition`             | `csv-protocol/src/transition.rs` | Already partially there                      |
| `store` / `state_store`  | `csv-storage`                    | Storage abstraction crate                    |
| `recovery_engine`        | `csv-coordinator/src/recovery/`  | Coordinator concern                          |
| `trust_package`          | `csv-verifier/src/trust.rs`      | Verification concern                         |
| `validator`              | `csv-verifier/src/validator.rs`  | Already has verifier.rs                      |
| `mcp`                    | `csv-mcp-server` (TS)            | TypeScript boundary, remove Rust stub        |
| `performance`            | `csv-observability`              | Observability concern                        |
| `adapter`                | `csv-protocol/src/backend.rs`    | Already has backend.rs                       |
| `certification`          | `csv-proof/src/certification.rs` | Already exists                               |
| `collections`            | inline in `csv-algebra`          | Pure types, no deps                          |
| `compatibility`          | `csv-protocol/src/version.rs`    | Version/compat concern                       |
| `wallet_types`           | `csv-sdk/src/wallet.rs`          | SDK boundary                                 |
| `zk_proof`               | `csv-verifier`                   | Verification concern                         |
| `data_authority`         | `csv-protocol`                   | Protocol concern                             |
| `runtime_health`         | `csv-observability`              | Observability concern                        |

### B-2 — Migrate csv-sdk off csv-core

`csv-sdk/Cargo.toml` depends on `csv-core` unconditionally. Replace each import:

```rust
// csv-sdk/src/lib.rs — BEFORE
use csv_core::wallet_types::WalletConfig;
use csv_core::client::ValidationClient;

// AFTER
use csv_sdk::wallet::WalletConfig;           // moved to sdk
use csv_protocol::backend::ValidationBackend; // or csv-verifier
```

After removing all use-sites, delete the dep from `csv-sdk/Cargo.toml`:
```toml
# DELETE THIS LINE:
csv-core = { path = "../csv-core" }
```

### B-3 — Guard via architecture tests

```rust
// csv-architecture/tests/architecture_guard.rs — ADD
#[test]
fn nothing_new_depends_on_csv_core() {
    let allowed = ["csv-core"]; // csv-core may depend on itself for tests
    let cargo_files = glob_cargo_tomls(workspace_root());
    for (path, content) in cargo_files {
        if path.contains("csv-core") { continue; }
        assert!(
            !content.contains("csv-core"),
            "{path} imports csv-core — migrate to target crate per dev plan"
        );
    }
}
```

### B-4 — Delete csv-core

Once zero crates import it (verified by the architecture guard above):
1. Remove from `Cargo.toml` workspace members array.
2. Delete the directory.
3. Create `csv-core/TOMBSTONE.md` in git history for reference.

---

## Workstream C — Phase-Specific Crash Recovery (4 Stubs)

`csv-runtime/src/transfer_coordinator.rs` has four recovery paths that
fall back to full re-execution instead of resuming at the correct phase.
The `execution_journal` already records phase transitions with `Entered/Completed/Failed`.
The missing piece: each `execute_from_*` method must read journal state and
skip already-completed phases.

### C-1 — execute_from_lock (LockConfirmed recovery)

Current stub: delegates to full `execute()`.
Required: read lock result from journal, skip lock broadcast, resume at
proof generation.

```rust
// csv-runtime/src/transfer_coordinator.rs
pub async fn execute_from_lock(
    &self,
    transfer: &CrossChainTransfer,
    adapter_registry: &dyn AdapterRegistry,
    ctx: RuntimeExecutionContext,
) -> Result<TransferReceipt, TransferCoordinatorError> {
    // 1. Load LockConfirmed journal entry to get lock_tx_hash and lock_height
    let lock_entry = self.execution_journal
        .latest_phase_entry(&transfer.id, TransferPhase::LockConfirmed)
        .await
        .map_err(|e| TransferCoordinatorError::RuntimeError(e.to_string()))?
        .ok_or_else(|| TransferCoordinatorError::RuntimeError(
            "No LockConfirmed journal entry found for recovery".to_string()
        ))?;

    // 2. Reconstruct Locked typestate from journal payload
    let locked = Locked::new(
        transfer.data.clone(),
        lock_entry.block_height,
        lock_entry.tx_hash_bytes.clone(),
    );

    // 3. Resume: advance through AwaitingFinality → ProofBuilding → ProofValidated → Minting
    self.execute_from_awaiting_finality(locked, transfer, adapter_registry, ctx).await
}
```

The journal entry payload schema (`ExecutionJournalEntry`) must include
`block_height: u64` and `tx_hash_bytes: Vec<u8>` — add if missing.

### C-2 — execute_from_proof (ProofValidated recovery)

Current stub: returns hard error `"Cannot resume from ProofValidated phase — transfer state lost"`.
Required: load proof bytes from journal, skip proof generation, go straight to mint.

```rust
pub async fn execute_from_proof(
    &self,
    transfer: &CrossChainTransfer,
    proof_bundle: csv_protocol::proof_types::ProofBundle,
    adapter_registry: &dyn AdapterRegistry,
) -> Result<TransferReceipt, TransferCoordinatorError> {
    // Journal the resume event
    self.execution_journal.record(
        &transfer.id,
        TransferPhase::MintingResumed,
        JournalStatus::Entered,
        None,
    ).await?;

    // Proceed directly to mint broadcast (proof already validated)
    let mint_result = adapter_registry
        .mint_sanad(&transfer.dest_chain_id, &transfer.sanad_id, &proof_bundle)
        .await
        .map_err(TransferCoordinatorError::AdapterError)?;

    self.execution_journal.record(
        &transfer.id,
        TransferPhase::MintSubmitted,
        JournalStatus::Completed,
        Some(mint_result.tx_hash.as_bytes().to_vec()),
    ).await?;

    self.execute_from_mint(&transfer.id, &mint_result.tx_hash, adapter_registry).await
}
```

For this to work, `ExecutionJournalEntry` must store proof bytes or a
content-addressed proof reference. Add `proof_payload: Option<Vec<u8>>` to the
journal entry struct (or store a `csv_hash::Hash` and look up from `csv-storage`).

### C-3 — AwaitingFinality recovery

Current: hard error `"Cannot resume from AwaitingFinality — transfer state lost"`.
Required: re-poll finality monitor with the proof height stored in journal.

```rust
TransferStage::AwaitingFinality => {
    let finality_entry = self.execution_journal
        .latest_phase_entry(&transfer_id, TransferPhase::AwaitingFinality)
        .await?
        .ok_or(TransferCoordinatorError::NotFound)?;

    let proof_height = finality_entry.block_height;
    let required_confs = ctx.policy.required_confirmations();

    // Poll current confirmations from chain
    let current = adapter_registry
        .get_confirmation_count(&transfer.source_chain_id, proof_height)
        .await
        .map_err(TransferCoordinatorError::AdapterError)?;

    if current >= required_confs {
        // Finality achieved — advance to ProofBuilding
        let awaiting = AwaitingFinality::new(transfer.data.clone(), proof_height, required_confs);
        let proof_building = awaiting.advance_to_proof_building(current)?;
        self.run_proof_building(proof_building, &transfer, adapter_registry).await
    } else {
        // Still waiting — re-arm the finality monitor
        self.enqueue_finality_check(transfer_id, proof_height, required_confs).await?;
        Ok(TransferReceipt::pending(transfer_id))
    }
}
```

This requires `AdapterRegistry` to expose `get_confirmation_count(&str, u64) -> Result<u32>`.
Add to the `AdapterRegistry` trait in `csv-runtime/src/adapter_registry.rs`.

### C-4 — ProofBuilding recovery (intermediate progress)

Current: delegates to `execute_from_lock` (loses proof-building progress).
Required: check if partial proof state was persisted; if so, resume; else restart from lock.

```rust
TransferStage::ProofBuilding => {
    // Check for persisted proof-in-progress
    let partial = self.execution_journal
        .latest_phase_entry(&transfer_id, TransferPhase::ProofBuildingCheckpoint)
        .await?;

    match partial {
        Some(entry) if entry.proof_payload.is_some() => {
            // Resume from checkpoint — pass partial state to proof engine
            let proof_bundle = self.proof_engine
                .resume_from_checkpoint(entry.proof_payload.unwrap())
                .await
                .map_err(|e| TransferCoordinatorError::RuntimeError(e.to_string()))?;
            self.execute_from_proof(&transfer, proof_bundle, adapter_registry).await
        }
        _ => {
            // No checkpoint — restart proof generation from lock
            self.execute_from_lock(&transfer, adapter_registry, ctx).await
        }
    }
}
```

Add `TransferPhase::ProofBuildingCheckpoint` to the `TransferPhase` enum in
`csv-protocol/src/transfer_state/mod.rs`. Proof engine must call
`journal.record(id, ProofBuildingCheckpoint, Entered, Some(partial_state))`
periodically during long proof generation.

### C-5 — Wire proof_payload into ExecutionJournalEntry

```rust
// csv-runtime/src/execution_journal.rs — ADD field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionJournalEntry {
    pub transfer_id: String,
    pub phase: TransferPhase,
    pub status: JournalStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub block_height: u64,              // ADD
    pub tx_hash_bytes: Vec<u8>,         // ADD (empty if not applicable)
    pub proof_payload: Option<Vec<u8>>, // ADD (proof bytes or checkpoint)
}
```

Add corresponding columns to the SQL migration:
```sql
-- csv-runtime/migrations/0002_journal_payload.sql
ALTER TABLE execution_journal ADD COLUMN block_height BIGINT NOT NULL DEFAULT 0;
ALTER TABLE execution_journal ADD COLUMN tx_hash_bytes BYTEA NOT NULL DEFAULT '';
ALTER TABLE execution_journal ADD COLUMN proof_payload BYTEA;
```

---

## Workstream D — Orphan Re-Wiring

Three crates survive csv-core removal only if re-wired to their correct layer.

### D-1 — csv-observability: add csv-protocol dependency

`csv-observability` currently has **zero csv-* deps**. It uses `workspace` deps
for serde/tokio/uuid but has no protocol awareness. Once csv-core is gone, any
code that imported `csv-core::performance` into observability will break.

Wire it properly:
```toml
# csv-observability/Cargo.toml — ADD
csv-protocol = { path = "../csv-protocol" }  # for TransferStage, event types
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
```

Move `csv-core::runtime_health` and `csv-core::performance` into
`csv-observability/src/health.rs` and `csv-observability/src/metrics/mod.rs`.

Export from observability's `lib.rs`:
```rust
pub mod health;    // formerly csv_core::runtime_health
pub mod metrics;   // formerly csv_core::performance
pub mod logging;   // existing
```

### D-2 — csv-schema: already wired, verify clean

`csv-schema` depends on `csv-codec` (correct — L2-ish). Verify no hidden
csv-core import exists after the migration:

```bash
grep -r "csv.core\|csv_core" csv-schema/src/
# Must return empty
```

### D-3 — csv-content: already wired, verify clean

`csv-content` depends on `csv-hash` (correct). Same verification:
```bash
grep -r "csv.core\|csv_core" csv-content/src/
# Must return empty
```

### D-4 — Add all three to architecture guard allowlist

```rust
// csv-architecture/tests/architecture_guard.rs
#[test]
fn orphan_crates_have_csv_protocol_or_hash_dep() {
    let must_have_protocol_dep = ["csv-observability", "csv-content", "csv-schema"];
    for crate_name in must_have_protocol_dep {
        let manifest = fs::read_to_string(
            workspace_root().join(format!("{crate_name}/Cargo.toml"))
        ).unwrap();
        assert!(
            manifest.contains("csv-protocol") || manifest.contains("csv-hash") || manifest.contains("csv-codec"),
            "{crate_name} has no csv-* dependency — will be orphaned when csv-core is removed"
        );
    }
}
```

---

## Workstream E — Infrastructure Cleanup

### E-1 — csv-examples: add Cargo.toml

`csv-examples/` contains Rust source files with no `Cargo.toml` — they cannot be compiled.

```toml
# csv-examples/Cargo.toml — CREATE
[package]
name = "csv-examples"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
csv-sdk = { path = "../csv-sdk", features = ["bitcoin"] }
csv-protocol = { path = "../csv-protocol" }
csv-hash = { path = "../csv-hash" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tracing-subscriber = "0.3"

[[example]]
name = "basic_transfer"
path = "examples/basic_transfer.rs"

[[example]]
name = "cross_chain"
path = "examples/cross_chain.rs"
```

Add `"csv-examples"` to the workspace members array in root `Cargo.toml`.
Run `cargo check -p csv-examples` — fix any compilation errors.

### E-2 — deployment/ vs deployments/ cleanup

`deployment/` (singular) is an incomplete template with zero addresses and no `verify.sh`.
`deployments/` (plural) is the real thing.

Actions:
1. Delete `deployment/` entirely OR rename it `deployment.template/` with a
   `README.md` that says: *"Template only. Actual deployments are in deployments/."*
2. Add missing `verify.sh` to `deployment.template/` as a stub with inline docs:
   ```bash
   #!/usr/bin/env bash
   # verify.sh — Verify a deployment against on-chain state
   # Usage: ./verify.sh <chain> <contract_address>
   # Actual implementation: see deployments/<chain>/verify.sh
   set -euo pipefail
   echo "ERROR: Use deployments/<chain>/verify.sh, not this template." >&2
   exit 1
   ```
3. Add a `ci_no_deploy_template` test in `.github/workflows/architecture.yml`
   that asserts `deployment/` contains no real addresses.

### E-3 — formal/ TLA+/Alloy in CI

Add a CI job that validates TLA+ models on every push to main:

```yaml
# .github/workflows/architecture.yml — ADD job
  formal-verification:
    name: Formal model check
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install TLA+ tools
        run: |
          wget -q https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar \
            -O /usr/local/lib/tla2tools.jar
      - name: Check TLA+ models
        run: |
          find formal/ -name "*.tla" | while read model; do
            java -cp /usr/local/lib/tla2tools.jar tlc2.TLC \
              -config "${model%.tla}.cfg" "$model" \
              -workers auto || exit 1
          done
      - name: Check Alloy models
        run: |
          find formal/ -name "*.als" | while read model; do
            java -jar /usr/local/lib/alloy.jar "$model" || exit 1
          done
```

If TLC config files (`.cfg`) don't yet exist alongside each `.tla`, create minimal ones:
```
SPECIFICATION Spec
INVARIANT TypeInvariant
PROPERTY LivenessProperty
```

### E-4 — development/ directory: create it

`csv-core/src/lib.rs` references `development/csv_migration_plan.md` in a
doc comment. The directory doesn't exist. Either:

**Option A** (preferred): Create it with the plan that already exists implicitly:
```
development/
  csv_migration_plan.md   — this document's content, maintained as living doc
  csv_wire_activation.md  — workstream A progress tracker
  csv_core_elimination.md — workstream B progress tracker
  recovery_stubs.md       — workstream C progress tracker
  adr/                    — Architecture Decision Records
    001-wire-boundary.md
    002-recovery-journal.md
    003-no-legacy-serde.md
```

**Option B**: Remove all references to `development/` from source comments
and point to this plan instead.

### E-5 — tests/ root: document as mirror

Add `tests/README.md` if it doesn't exist:
```markdown
# tests/

This directory is a MIRROR of authoritative tests in crate-local `tests/` dirs.
Do not edit files here directly. Changes in crate `tests/` propagate here.
Authoritative locations: csv-runtime/tests/, csv-protocol/tests/, csv-core/tests/
```

---

## Workstream F — Architecture Enforcement Hardening

### F-1 — Add csv-wire usage check to dep_graph_constitution

```rust
// csv-architecture/tests/dep_graph_constitution.rs — ADD test
#[test]
fn l1_through_l4_route_wire_encoding_through_csv_wire() {
    let metadata = MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .expect("cargo metadata must succeed");

    let wire_users: Vec<_> = metadata.packages.iter()
        .filter(|pkg| {
            // L2-L4 crates that should NOT have direct serde
            matches!(pkg.name.as_str(),
                "csv-hash" | "csv-protocol" | "csv-proof" | "csv-verifier" | "csv-codec"
            )
        })
        .filter(|pkg| {
            pkg.dependencies.iter().any(|d| d.name == "serde")
        })
        .map(|pkg| pkg.name.clone())
        .collect();

    assert!(
        wire_users.is_empty(),
        "These crates have direct serde deps — must route through csv-wire: {:?}",
        wire_users
    );
}
```

### F-2 — Add csv-core elimination check

```rust
#[test]
fn csv_core_has_no_reverse_dependents() {
    let metadata = MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .unwrap();

    let dependents: Vec<_> = metadata.packages.iter()
        .filter(|pkg| pkg.name != "csv-core")
        .filter(|pkg| {
            pkg.dependencies.iter().any(|d| d.name == "csv-core")
        })
        .map(|pkg| pkg.name.clone())
        .collect();

    assert!(
        dependents.is_empty(),
        "csv-core still has dependents — migration incomplete: {:?}",
        dependents
    );
}
```

### F-3 — Strengthen L7 isolation check

Currently adapters are checked for L5/L6 imports. Add csv-wire import check
(adapters must not bypass csv-wire by importing serde directly):

```rust
// In dependency_dag_has_no_upward_edges — ADD:
// Adapters (L7) must use csv-wire for serde, not direct serde
if from_layer == 7 {
    let direct_serde = pkg.dependencies.iter().any(|d| d.name == "serde");
    if direct_serde {
        violations.push(format!(
            "L7 adapter {} imports serde directly — must use csv-wire for serialization",
            pkg.name
        ));
    }
}
```

### F-4 — Recovery test coverage gate

Add a gate that fails CI if crash-recovery tests are not present for all phases:

```rust
// csv-architecture/tests/architecture_guard.rs — ADD
#[test]
fn all_transfer_phases_have_crash_recovery_tests() {
    let phases = [
        "LockSubmitted", "LockConfirmed", "AwaitingFinality",
        "ProofBuilding", "ProofValidated", "MintSubmitted", "MintConfirmed",
    ];
    let test_dir = workspace_root().join("csv-runtime/tests");
    let test_content = fs::read_dir(&test_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        .map(|e| fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");

    for phase in phases {
        assert!(
            test_content.contains(phase),
            "No crash-recovery test found for phase {phase} in csv-runtime/tests/"
        );
    }
}
```

---

## Execution Order & Dependencies

```
A-1  ──► A-2  ──► A-3  ──► A-4  ──► A-5
                                      │
                                      ▼
B-1  ──► B-2  ──► (A-5 passes) ──► B-3  ──► B-4
                                      │
         D-1  ◄───────────────────────┘
         D-2
         D-3
         D-4

C-1  ──► C-2  ──► C-3  ──► C-4  ──► C-5
(C-5 unblocks F-4)

E-1  (independent)
E-2  (independent)
E-3  (independent)
E-4  (independent, do early)
E-5  (independent)

F-1  (after A-3)
F-2  (after B-3)
F-3  (after A-4)
F-4  (after C-5)
```

**Do E-4 first** — creates `development/` with this plan as living doc so
all future PRs have a tracking location.

---

## Success Criteria

| Check | Command | Passing when |
|---|---|---|
| No serde in L0–L4 | `cargo deny check bans` | Zero violations |
| No csv-core dependents | `cargo test -p csv-architecture` | All tests pass |
| All recovery paths tested | `cargo test -p csv-runtime` | crash_recovery fully green |
| Wire boundary complete | `cargo test -p csv-architecture -- wire` | `l1_through_l4_route_wire` passes |
| Formal models in CI | `.github/workflows/architecture.yml` | `formal-verification` job green |
| Examples compile | `cargo check -p csv-examples` | Zero errors |
| Dep graph clean | `cargo test -p csv-architecture -- dep_graph` | `dependency_dag_has_no_upward_edges` passes |
