# Protocol Invariants — DO NOT VIOLATE

This document defines the fundamental invariants of the CSV (Client-Side Validation) protocol. These invariants are non-negotiable and exist for security reasons. Any code change that violates these invariants must be rejected.

## Invariant 1: Seal IDs Must Come From Real Blockchain Transactions

**Rule:** A `SealPoint.seal_id` must come from a real blockchain transaction.

**Prohibited:**

- Never construct seal IDs from timestamps
- Never construct seal IDs from UUIDs
- Never construct seal IDs from random bytes
- Never use "fake" or "mock" seal IDs in production

**Correct Pattern:**

```rust
// Use the chain adapter's create_seal() method
let seal_ref = chain_adapter.create_seal(value)?;
// seal_ref.seal_id now contains the actual UTXO txid, PDA address, etc.
```

**Security Impact:** Fake seal IDs enable double-spend attacks because the seal is not actually consumed on-chain.

**Error Code:** `CORE_SEAL_NOT_ANCHORED` is raised when a fake seal is detected.

---

## Invariant 2: Commitments Must Be Published On-Chain Before Proof Building

**Rule:** A `Commitment` must be published on-chain before a `ProofBundle` is built.

**Prohibited:**

- Never build a `ProofBundle` without an `CommitAnchor`
- Never use simulated/mock anchors in production
- Never skip the publication step

**Correct Pattern:**

```rust
// 1. Create and publish the commitment
let anchor = anchor_layer.publish(commitment, seal)?;

// 2. Wait for finality
let finality = anchor_layer.verify_finality(anchor.clone())?;

// 3. Build the proof bundle with real anchor data
let proof_bundle = ProofBundle::new(
    dag_segment,
    signatures,
    seal_ref,
    anchor,      // Real anchor from chain
    inclusion,   // Verified inclusion proof
    finality,    // Verified finality proof
)?;
```

**Security Impact:** Proof bundles without on-chain anchors provide no security guarantee. They can be forged by anyone.

---

## Invariant 3: Sanads Must Pass ConsignmentValidator Before Entering AppState

**Rule:** A `Sanad` must pass all 5 validation steps of `ConsignmentValidator` before being accepted into `AppState`.

**Required Steps:**

1. Structural Validation — version, schema, required fields
2. Commitment Chain Validation — genesis to latest integrity
3. Seal Consumption Validation — double-spend detection
4. State Transition Validation — valid evolution rules
5. Final Acceptance Decision — all checks must pass

**Prohibited:**

- Never accept a Sanad without running all 5 validation steps
- Never skip validation for "trusted" sources
- Never cache validation results across consignment updates

**Correct Pattern:**

```rust
let validator = ConsignmentValidator::new();
let report = validator.validate_consignment(&consignment, ChainId::Bitcoin);

if !report.passed {
    // Reject the consignment — do not add to AppState
    return Err(Error::ValidationFailed(report.summary));
}

// Only now add to AppState
app_state.add_sanad(sanad)?;
```

**Security Impact:** Skipping validation allows fraudulent state transitions to enter the wallet state, enabling theft.

---

## Invariant 4: Balances Are Stored as u64 Native Units

**Rule:** Balances must be stored as `u64` native units (satoshis, lamports, MIST, octas, wei).

**Prohibited:**

- Never store balances as `f64` (floating point)
- Never store balances as human-readable strings ("1.5 BTC")
- Never use JSON numbers for financial amounts (precision loss)

**Correct Pattern:**

```rust
pub struct ChainAccount {
    /// Balance in native chain units (satoshis, wei, lamports, etc.)
    pub balance_raw: u64,
}

// Display conversion uses integer arithmetic only
let whole = balance_raw / 100_000_000;
let fractional = balance_raw % 100_000_000;
let display = format!("{}.{} BTC", whole, fractional);
```

**Security Impact:** Floating point rounding errors and precision loss can be exploited for value manipulation (e.g., 0.1 + 0.2 != 0.3 bugs).

---

## Invariant 5: Cross-Chain Transfers Must Follow the TransferState Machine

**Rule:** All cross-chain transfers must progress through the `TransferState` machine states in order:

```
Locking → AwaitingFinality → BuildingProof → ProofReady → Minting → Complete
```

**Prohibited:**

- Never skip from `Locking` directly to `Minting`
- Never build proofs before finality is reached
- Never retry a failed transfer without checking `recoverable` flag

**Correct Pattern:**

```rust
// Drive the state machine forward
match transfer.state {
    TransferState::Locking { source_tx, lock_height } => {
        // Check confirmations
        let confirmations = chain.get_confirmations(source_tx).await?;
        if confirmations >= REQUIRED_CONFIRMATIONS {
            transfer.state = TransferState::AwaitingFinality {
                confirmations_needed: REQUIRED_CONFIRMATIONS,
                confirmations_have: confirmations,
            };
        }
    }
    TransferState::AwaitingFinality { .. } => {
        // Wait for finality before building proof
        if finality_reached {
            transfer.state = TransferState::BuildingProof;
        }
    }
    // ... etc
}
```

**Security Impact:** Skipping steps enables attacks like minting before the source seal is actually consumed, allowing double-spends.

---

## Invariant 6: SealRegistry Must Be Checked Before Accepting Any Transfer

**Rule:** `SealRegistry::check_consumed` must run before accepting any incoming transfer.

**Prohibited:**

- Never accept a transfer without double-spend check
- Never rely on client-side caching alone
- Never skip the check for "fast path" optimizations

**Correct Pattern:**

```rust
// Check the cross-chain seal registry for double-spends
match registry.check_seal_status(&seal_ref) {
    SealStatus::Unconsumed => {
        // Safe to proceed
        accept_transfer(transfer)?;
    }
    SealStatus::ConsumedOnChain { chain, .. } => {
        // Reject — this seal was already used
        return Err(Error::DoubleSpendDetected(chain));
    }
    SealStatus::DoubleSpent => {
        // Critical security alert
        return Err(Error::DoubleSpendAttackDetected);
    }
}
```

**Security Impact:** Without this check, an attacker can reuse the same seal across multiple transfers, stealing funds.

---

## Invariant 7: Domain Separation Must Be Used for All Hashes

**Rule:** All cryptographic hashes must use domain separation to prevent cross-chain replay attacks.

**Prohibited:**

- Never hash raw data without domain prefix
- Never use the same hash function across different chains without separation
- Never omit chain identifier from commitment hashes

**Correct Pattern:**

```rust
// Domain-separated commitment hash
let commitment = hash(
    domain_separator ||      // Chain-specific domain
    chain_id ||              // Chain identifier
    contract_id ||           // Contract identifier
    previous_commitment ||   // Previous in chain
    transition_payload_hash || // Transition data
    seal_hash                // Seal reference
);
```

**Security Impact:** Without domain separation, a commitment from one chain can be replayed on another chain, enabling cross-chain double-spends.

---

## Invariant 8: Mint Authorization MUST Use VerificationResult::meets_chain_thresholds()

**Rule:** Mint authorization MUST use `VerificationResult::meets_chain_thresholds(&caps)`, never a scalar enum comparison. `VerificationAssurance` is a display signal only.

**Prohibited:**

- Never use `assurance >= ConsensusBound` or similar scalar comparisons for mint gates
- Never bypass `VerificationResult::meets_chain_thresholds()` for "fast path" optimizations
- Never treat `VerificationAssurance` as a security-critical value

**Correct Pattern:**

```rust
// CORRECT: Use the typed verification result
let result = verifier.verify_proof_bundle(&bundle)?;
if result.meets_chain_thresholds(&chain_capabilities) {
    mint_sanad(result)?;
}

// PROHIBITED: Scalar enum comparison
if result.assurance >= VerificationAssurance::ConsensusBound {
    mint_sanad(result)?; // This bypasses chain-specific threshold checks
}
```

**Security Impact:** Scalar enum comparison is the root cause of silent verification bypass. The `VerificationResult` type encodes chain-specific threshold logic that scalar enums cannot represent.

---

## Invariant 9: ReplayDatabase Insert-Before-Mint with Compare-and-Swap

**Rule:** `ReplayDatabase::insert_if_absent()` MUST succeed with compare-and-swap semantics before `mint_sanad()` is called. A `contains()` check alone is not sufficient.

**Prohibited:**

- Never call `mint_sanad()` before `insert_if_absent()` succeeds
- Never use a blind `contains()` check followed by insert (race condition under concurrent coordinators)
- Never skip replay database insertion for "trusted" sources

**Correct Pattern:**

```rust
// CORRECT: CAS insert before mint
let replay_id = ReplayId::from_transfer_inputs(&transfer);
match replay_db.insert_if_absent(&replay_id) {
    Ok(Inserted) => {
        // Safe to proceed with mint
        mint_sanad(sanad)?;
    }
    Ok(AlreadyExists) => {
        return Err(Error::ReplayAttackDetected);
    }
    Err(e) => {
        return Err(e);
    }
}

// PROHIBITED: Blind contains check
if !replay_db.contains(&replay_id) {
    replay_db.insert(&replay_id); // Race condition here
    mint_sanad(sanad)?; // May mint duplicate under concurrent coordinators
}
```

**Security Impact:** Without CAS semantics, concurrent coordinators can both pass the `contains()` check and mint the same transfer, enabling double-mint attacks.

---

## Invariant 10: Signature Scheme MUST Match the Source Chain

**Rule:** Each `ProofBundle` MUST carry the signature scheme used to produce its authorizing signatures. Runtime verification MUST compare that bundle scheme against the source chain adapter's configured scheme and reject any mismatch before cryptographic verification.

**Prohibited:**

- Never hardcode `SignatureScheme::Secp256k1` in a generic verification path
- Never accept a bundle whose scheme disagrees with the source chain adapter
- Never infer a default scheme when the proof bundle has explicit scheme metadata

**Correct Pattern:**

```rust
let bundle_scheme = proof_bundle.signature_scheme;
let expected_scheme = adapter_registry.signature_scheme(&source_chain)?;
if bundle_scheme != expected_scheme {
    return Err(Error::SignatureSchemeMismatch);
}
verifier.verify_proof_bundle(&proof_bundle, expected_scheme)?;
```

**Security Impact:** Verifying Ed25519 chains (Solana, Aptos, Sui) under Secp256k1 causes proofs to pass or fail for the wrong cryptographic reason and can create silent cross-chain verification failures.

---

## Invariant 11: ZkVerifierRegistry Must Use Real Chain-Anchored Keys

**Rule:** `ZkVerifierRegistry` must be initialized from real chain-anchored keys. `default_verifier_registry()` is test-only and must never appear in production code paths.

**Prohibited:**

- Never use `default_verifier_registry()` in production code
- Never initialize verifier registries with empty or placeholder keys
- Never skip verifier key validation in production paths

**Correct Pattern:**

```rust
// CORRECT: Initialize from real chain-anchored keys
#[cfg(not(test))]
let registry = ZkVerifierRegistry::from_chain_config(&chain_config)?;

#[cfg(test)]
let registry = default_verifier_registry(); // Test-only

// PROHIBITED: Using test registry in production
let registry = default_verifier_registry(); // Zero-length keys, no security
```

**Security Impact:** Placeholder verifier keys provide no security. Any proof can verify against an empty registry, enabling complete bypass of ZK verification.

---

## RPC Trust Model

**This section documents the explicit trust stance regarding RPC (Remote Procedure Call) nodes in the CSV protocol.**

### Position

The CSV protocol uses a **quorum RPC model** as its Stage 1 operational stance. This means:

- **RPC-minimized, not RPC-free**: The protocol reduces trust surface compared to a single trusted node but does not eliminate RPC trust entirely.
- **Quorum of independent nodes**: Multiple independent RPC providers are queried for the same evidence. Disagreement among providers causes rejection.
- **Collusion risk**: A quorum of colluding or compromised RPC nodes can still deliver false finality evidence. This is an **accepted pragmatic position for Stage 1**, not a protocol violation.

### Quorum Parameters

The quorum model operates with the following parameters (configurable per chain):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `min_providers` | 3 | Minimum number of independent RPC providers to query |
| `agreement_threshold` | 2/3 | Fraction of providers that must agree |
| `timeout_ms` | 5000 | Maximum time to wait for a single provider response |
| `finality_confirmations` | Configurable per chain | Number of confirmations required before evidence is accepted |

### Evidence Sources

The protocol relies on RPC-delivered evidence for:

1. **Inclusion proofs**: Merkle/MPT/checkpoint proofs delivered by RPC nodes
2. **Finality evidence**: Finality proofs (PoW depth, BFT certificates, checkpoint hashes)
3. **Seal registry status**: Whether a seal has been consumed on-chain
4. **Transaction receipts**: Confirmation of mint transactions on destination chains

### Light Client Roadmap (Stage 3)

Truly trust-minimized verification requires embedded light clients per chain. These are multi-month engineering efforts and are **Stage 3 targets, not Stage 1 requirements**:

| Chain | Light Client Type | Status |
|-------|-------------------|--------|
| Bitcoin | Header chain validator (cumulative PoW from genesis) | Roadmap |
| Ethereum | Consensus layer client (BLS signatures from validator set) | Roadmap |
| Solana | Ledger hash chain follower | Roadmap |
| Aptos | BFT certificate validator (known validator set rotation) | Roadmap |
| Sui | BFT certificate validator (known validator set rotation) | Roadmap |

The `FinalityVerifier` trait in `csv-protocol/src/finality` is the abstraction point for swapping in light client implementations as they become available — the coordinator does not need to change.

### Invariant (Target Model, Stage 3)

**The invariant that must hold in the target model (Stage 3):**

> No transfer completes without an independent on-chain confirmation of the mint transaction that does not come from the same adapter instance that submitted it.

**Current Status (Stage 1):** This is an **unresolved problem**
This prevents Byzantine-destination attacks where a malicious destination adapter could fake mint confirmations.

**Byzantine destination adapter:** The destination chain adapter
returns a `MintReceipt` claiming success. The coordinator currently trusts this. Before marking a transfer complete, the coordinator must independently verify the mint transaction is present on-chain — not via the same adapter instance that performed the mint, but via a quorum verification call against independent RPC nodes.
The coordinator currently trusts the adapter's `MintReceipt`. This invariant is presented as the target security model, not current behavior.

### Observability

The observability stack tracks RPC trust metrics:

- **RPC quorum disagreements**: Count of cases where providers returned divergent evidence
- **Provider health**: Per-provider success rates, latency, and failure patterns
- **Finality verification**: Whether finality evidence was accepted or rejected

These metrics enable operators to detect when the quorum model is being abused and switch to fallback providers or light clients.

---

## Audit Checklist for Code Reviews

When reviewing code changes, verify:

- [ ] No fake seal IDs are constructed
- [ ] Proof bundles always include real CommitAnchors
- [ ] ConsignmentValidator runs before accepting Sanads
- [ ] Balances are u64 native units only
- [ ] TransferState machine is not skipped
- [ ] SealRegistry check runs before transfer acceptance
- [ ] Domain separation is used for all hashes
- [ ] No `Result<bool>` returns from verifier functions (use `VerificationResult`)
- [ ] `SignatureScheme::default()` returns `Secp256k1` (not `MlDsa65`)
- [ ] `default_verifier_registry()` absent from non-test scope
- [ ] `VerificationResult::meets_chain_thresholds()` used for mint gate
- [ ] `ReplayDatabase::insert_if_absent()` called with CAS before mint
- [ ] Proof bundle signature scheme matches the source chain adapter

**Violations of any of these invariants must block the PR.**

---

## Invariant: Finality Is Never Optional

**Rule:** All runtime modes (Normal, Degraded, Unsafe) MUST enforce strict finality.

**Prohibited:**

- Setting `enforces_strict_finality()` to `false` in any mode
- Using placeholder finality proofs (e.g., `FinalityProof::new(vec![0u8; 32], ...)`)
- Commenting out finality checks with `// TODO` or `// FIXME`

**Correct Pattern:**

```rust
// All modes enforce strict finality
pub fn enforces_strict_finality(&self) -> bool {
    true // finality is never optional
}
```

**Security Impact:** Bypassing finality enables double-spend attacks where a transfer is minted before the source lock is irreversibly confirmed.

---

## Invariant: CLI Holds No Protocol Authority State

**Rule:** The CLI (`csv-cli`) MUST NOT store leases, transfers, or any protocol authority state.

**Prohibited:**

- `UnifiedStateManager` storing leases in-memory
- CLI calling `store_lease()` or `get_lease()`
- CLI implementing transfer execution logic

**Correct Pattern:**

```rust
// CLI is a stateless client — all protocol authority lives in csv-runtime
let lease_token = csv_runtime_client.acquire_lease(...).await?;
// Display the token; do NOT store in CLI state
```

**Security Impact:** CLI authority state breaks the authority model and enables race conditions between CLI and runtime.

---

## Invariant: Execution Journal Provides Crash-Safe Recovery

**Rule:** Every transfer phase transition MUST be recorded in the execution journal before and after execution.

**Status:** ✅ Implemented (Phase 9, 2026-06-13)

**Implementation:**
- ExecutionJournal trait in csv-runtime/src/execution_journal.rs
- InMemoryJournal for testing
- RocksDbExecutionJournal for production (feature-gated)
- TransferPhaseEntry with transfer context for crash recovery
- TransferCoordinator.resume_transfer() for recovery from any stage

**Prohibited:**

- Executing phases without journal entries
- Crash between phases without recovery path
- Using in-memory-only state for transfer coordination

**Correct Pattern:**

```rust
// Record BEFORE phase execution
journal.record(TransferPhaseEntry { phase: ..., outcome: PhaseOutcome::Entered, .. })?;
// Execute phase
// Record AFTER phase execution
journal.record(TransferPhaseEntry { phase: ..., outcome: PhaseOutcome::Completed, .. })?;
```

**Security Impact:** Without crash-safe journaling, crashes between phases cause duplicate mints or lost transfers.

---

## Questions?

If you're unsure whether your change violates an invariant:

1. Read the relevant section of `csv-docs/PLAN.md`
2. Ask in #protocol-security channel before merging

**When in doubt, ask. Security is everyone's responsibility.**
