---
id: PROOF-INCLUSION-APT-001
title: "Aptos inclusion proof build/verify use mismatched semantics"
theme: "legacy chain-native inclusion proof path"
crate: csv-aptos
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-aptos/src/ops.rs"
target_patterns:
  - "impl ChainProofProvider for AptosBackend"
  - "async fn build_inclusion_proof"
  - "self.event_builder"
target_file_2: "csv-adapters/csv-aptos/src/chain_verification.rs"
target_patterns_2:
  - "pub fn verify_inclusion_native"
  - "proof.proof_bytes.len() < 32"
interface_files:
  - "csv-sdk/src/runtime.rs"
  - "csv-cli/src/commands/proofs.rs"
  - "csv-adapters/csv-aptos/src/runtime_adapter.rs"
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
reference_crate: "csv-ethereum"
reference_file: "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
reference_patterns:
  - "async fn build_inclusion_proof"
  - "build_inclusion_proof_fails_closed_without_receipt"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-aptos --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-aptos --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files: []
cross_boundary_check: false
---

## Problem

Same bug class as `PROOF-INCLUSION-ETH-001`, on the Aptos adapter.
`AptosBackend`'s `ChainProofProvider::build_inclusion_proof`
(`csv-adapters/csv-aptos/src/ops.rs:692-738`) does not build a real Aptos
inclusion proof:

```rust
// Get block/ledger info
let ledger = self.rpc().get_ledger_info().await...?;

// Build event proof - use a default seal address
let seal_address = [0u8; 32];
let event_data = self
    .event_builder
    .build(*commitment.as_bytes(), seal_address);

// Convert ledger version to 32-byte hash
let mut block_hash_bytes = [0u8; 32];
let version_bytes = ledger.ledger_version.to_le_bytes();
block_hash_bytes[..8].copy_from_slice(&version_bytes);

// In a real implementation, we would use the anchor_id (which should be the
// transaction hash) to fetch the transaction and construct a proper proof.
...
Ok(CoreInclusionProof {
    proof_bytes: event_data,
    block_hash: Hash::new(block_hash_bytes),
    ...
})
```

`proof_bytes` is again a synthetic, locally-constructed event
(`event_builder.build` over the commitment and a hardcoded zero
`seal_address`) — not a real Merkle/accumulator inclusion witness for any
Aptos transaction or state proof. `block_hash` is a repackaging of the current
ledger version, not a real accumulator root tied to the transaction being
proven.

`verify_inclusion_native` (`csv-adapters/csv-aptos/src/chain_verification.rs:12-56`)
does not check `proof.proof_bytes` against any independently-fetched chain
state at all — it only checks structural properties of the proof the client
itself supplied:

```rust
if proof.proof_bytes.len() < 32 {
    return Ok(false);
}
if *proof.block_hash.as_bytes() == [0u8; 32] {
    return Err(...);
}
// Verify commitment is present in proof data
if !proof.proof_bytes.windows(commitment_bytes.len()).any(|window| window == commitment_bytes) {
    return Err(...);
}
Ok(true)
```

Since `proof_bytes` was built by embedding the commitment into a
locally-constructed event in the first place, "commitment is present in
proof_bytes" is trivially satisfiable by construction — this never touches
Aptos's real accumulator-based state proof. Build and verify are, at best,
checking that the client didn't corrupt its own fabricated payload; neither
step performs real cryptographic inclusion verification against on-chain
state.

## Why it matters

Reachable via `csv proof generate --chain aptos <sanad_id>` / `csv proof
verify` (`csv-cli/src/commands/proofs.rs::cmd_generate` →
`csv-sdk::ChainRuntime::generate_proof` →
`adapter.build_inclusion_proof(...)`). This violates the "no placeholder
verification" and "no fabricated blockchain state" invariants
(`.agents/AGENT.md §1.1, §1.2`).

**Scoping note (important, do not re-litigate):** this is a separate, legacy
proof-bundle path from the one the tested cross-chain mint/lock flow actually
uses. `csv-runtime::TransferCoordinator` calls `ChainProofPort::build_inclusion_proof`
via `csv-adapters/csv-aptos/src/runtime_adapter.rs`, a different implementation
from the one in `ops.rs`. The mint/lock transfer flow is not necessarily
affected by this specific bug — confirm the Aptos `runtime_adapter.rs`
inclusion path independently as part of this ticket's investigation, the same
way `PROOF-INCLUSION-ETH-001` confirmed it for Ethereum (that ticket found
Ethereum's runtime-adapter path is correctly fail-closed-tested via
`build_inclusion_proof_fails_closed_without_receipt`; verify whether Aptos's
runtime adapter has equivalent coverage before assuming parity).

## Task

Investigate whether `ChainProofProvider::build_inclusion_proof` on
`AptosBackend` (`ops.rs`) has any caller besides the standalone `csv proof
generate`/`csv proof verify` CLI command path. Then do one of:

- **(a) Reimplement.** Rebuild `build_inclusion_proof`/`verify_inclusion_native`
  to perform a real Aptos state/transaction inclusion proof (accumulator proof
  or transaction-by-version proof against a real ledger root), consistent with
  whatever correct pattern the Aptos `runtime_adapter.rs` uses for the mint/lock
  path, or with the pattern established by fixing `PROOF-INCLUSION-ETH-001`
  first (see its pattern note in `development/agent-workflow/pattern_notes/` if
  it exists yet).
- **(b) Retire/redirect.** If this legacy path has no remaining callers besides
  the standalone CLI command and RFC-0012's verifier-attested mint model has
  superseded it, deprecate/remove the CLI command's use of this path and route
  `csv proof generate`/`csv proof verify` through the correct
  `runtime_adapter.rs`-style path instead, updating CLI help text accordingly.

Prefer (b) if the investigation confirms there are no other callers.

## Acceptance criteria

- [ ] No code path builds an inclusion "proof" that its own paired verifier
      cannot meaningfully validate.
- [ ] `csv proof generate/verify --chain aptos` either performs real inclusion
      verification against on-chain state, or is clearly routed through the
      correct `runtime_adapter.rs`-style path (with CLI help text updated to
      match).
- [ ] If retired, `ChainProofProvider::build_inclusion_proof` on
      `AptosBackend` is either removed or made to fail closed with a clear
      "use the runtime path" error rather than returning a fabricated proof.
- [ ] Tests cover a real Aptos inclusion proof succeeding and a
      forged/mismatched proof being rejected.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search (`ChainProofProvider::build_inclusion_proof`,
      `event_builder.build`) confirms no other production caller of the old
      fabricated-event path remains untracked.

## Notes

Same bug class as `PROOF-INCLUSION-ETH-001` — fix whichever ticket lands
first, then write (or update) a pattern note in
`development/agent-workflow/pattern_notes/` (see `PATTERN_NOTE_TEMPLATE.md`)
covering the reusable shape ("real chain-native inclusion proof, build side
must produce data the verify side actually checks against independently
fetched chain state") so the other ticket can reuse it rather than
rediscovering the fix independently.
