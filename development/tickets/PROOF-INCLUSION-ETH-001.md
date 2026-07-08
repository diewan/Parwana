---
id: PROOF-INCLUSION-ETH-001
title: "Ethereum inclusion proof build/verify use mismatched semantics"
theme: "legacy chain-native inclusion proof path"
crate: csv-ethereum
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-ethereum/src/ops.rs"
target_patterns:
  - "impl ChainProofProvider for EthereumBackend"
  - "async fn build_inclusion_proof"
  - "self.event_builder"
target_file_2: "csv-adapters/csv-ethereum/src/chain_verification.rs"
target_patterns_2:
  - "pub fn verify_inclusion_native"
  - "state_root_bytes != proof.proof_bytes.as_slice()"
interface_files:
  - "csv-sdk/src/runtime.rs"
  - "csv-cli/src/commands/proofs.rs"
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
reference_crate: "csv-ethereum"
reference_file: "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
reference_patterns:
  - "async fn build_inclusion_proof"
  - "build_inclusion_proof_fails_closed_without_receipt"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-ethereum --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-ethereum --all-features"
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

`EthereumBackend`'s `ChainProofProvider::build_inclusion_proof`
(`csv-adapters/csv-ethereum/src/ops.rs:1134-1181`) does not build a real
Ethereum inclusion proof. It fetches the block at `block_height`, then:

```rust
// Build event proof for the commitment
let seal_address = [0u8; 32];
let event_data = self
    .event_builder
    .build(*commitment.as_bytes(), seal_address);

// Build MPT proof for the transaction containing the event
// This would require finding the transaction that emitted the event
let _proof_data = serde_json::to_vec(&block)
    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

// In a real implementation, we would use the anchor_id (which should be the
// transaction hash) to fetch the specific transaction and construct a proper
// inclusion proof.
...
Ok(CoreInclusionProof {
    proof_bytes: event_data,
    block_hash: Hash::new(block.state_root),
    ...
})
```

`proof_bytes` is a synthetic, locally-constructed event (`event_builder.build`
over the commitment and a hardcoded zero `seal_address`), not any real
transaction-receipt or state-trie inclusion witness. The comments in the
function candidly admit this ("This would require finding the transaction
that emitted the event", "In a real implementation, we would..."). Meanwhile
`block_hash` is set from the block's real `state_root`.

`verify_inclusion_native`
(`csv-adapters/csv-ethereum/src/chain_verification.rs:18-68`) then does:

```rust
let state_root_bytes: &[u8] = block.state_root.as_ref();
if state_root_bytes != proof.proof_bytes.as_slice() {
    return Ok(false);
}
```

This compares the freshly-fetched real block `state_root` against
`proof.proof_bytes` — which, per the build side above, holds the fabricated
event data, not a state root. A proof built by this adapter's own
`build_inclusion_proof` will essentially never satisfy this check (the
lengths/contents don't correspond), and even if it coincidentally did, the
subsequent "commitment present in proof_bytes" check
(`chain_verification.rs:41-49`) is trivially satisfiable because the client
embeds the commitment into `proof_bytes` itself via `event_builder.build`.
Build and verify are checking two different things — this is not a real
cryptographic inclusion check in either direction.

## Why it matters

This is reachable via the documented `csv proof generate --chain ethereum
<sanad_id>` / `csv proof verify` CLI commands
(`csv-cli/src/commands/proofs.rs::cmd_generate`, which calls
`csv-sdk`'s `ChainRuntime::generate_proof`, which calls
`adapter.build_inclusion_proof(...)` at `csv-sdk/src/runtime.rs:566-572`).
It directly contradicts the "no placeholder verification" and "no fabricated
blockchain state" invariants (`.agents/AGENT.md §1.1, §1.2`) — the function
fabricates a locally-constructed "event" and calls it an inclusion proof, and
the paired verifier does not actually check it against real chain state in a
way that means anything.

**Scoping note (important, do not re-litigate):** this is a separate, legacy
proof-bundle path from the one the tested cross-chain mint/lock flow actually
uses. `csv-runtime::TransferCoordinator` calls `ChainProofPort::build_inclusion_proof`
via `csv-adapters/csv-ethereum/src/runtime_adapter.rs`, which is a different,
correctly implemented and fail-closed-tested inclusion path (see
`build_inclusion_proof_fails_closed_without_receipt` and the four other
`build_inclusion_proof_fails_closed_*` tests in that file). The mint/lock
transfer flow is **not** affected by this bug — only the standalone `csv proof
generate` / `csv proof verify` command path (`ChainProofProvider` on
`EthereumBackend` in `ops.rs`) is.

## Task

Investigate whether `ChainProofProvider::build_inclusion_proof` on
`EthereumBackend` (`ops.rs`) has any caller besides the standalone `csv proof
generate`/`csv proof verify` CLI command path (via `csv-sdk::ChainRuntime`).
Then do one of:

- **(a) Reimplement.** Rebuild `build_inclusion_proof`/`verify_inclusion_native`
  to perform a real Ethereum MPT inclusion proof against the actual
  transaction/receipt trie and state root — consistent with what
  `runtime_adapter.rs`'s `ChainProofPort` implementation does correctly for the
  mint/lock path (fetch the real transaction/receipt for `anchor_id`, build a
  real Merkle-Patricia-Trie proof, verify it against the block's real
  `state_root` or `receipts_root`).
- **(b) Retire/redirect.** If investigation confirms this legacy
  `ChainProofProvider` path has no remaining callers besides the standalone CLI
  command, and RFC-0012's verifier-attested mint model has superseded it,
  deprecate/remove the CLI command's use of this path and route `csv proof
  generate`/`csv proof verify` through the correct `runtime_adapter.rs`-style
  inclusion path instead, updating CLI help text to describe what is actually
  being verified.

Prefer (b) if the investigation confirms there are no other callers — it
avoids maintaining two divergent Ethereum inclusion-proof implementations.

## Acceptance criteria

- [ ] No code path builds an inclusion "proof" that its own paired verifier
      cannot meaningfully validate.
- [ ] `csv proof generate/verify --chain ethereum` either performs real MPT
      inclusion verification, or is clearly routed through the correct
      `runtime_adapter.rs`-style path (with CLI help text updated to match).
- [ ] If retired, `ChainProofProvider::build_inclusion_proof` on
      `EthereumBackend` is either removed or made to fail closed with a clear
      "use the runtime path" error rather than returning a fabricated proof.
- [ ] Tests cover a real Ethereum inclusion proof succeeding and a
      forged/mismatched proof being rejected.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search (`ChainProofProvider::build_inclusion_proof`,
      `event_builder.build`) confirms no other production caller of the old
      fabricated-event path remains untracked.

## Notes

`PROOF-INCLUSION-APT-001` is the same bug class on Aptos. If this ticket is
picked up first, write a pattern note in
`development/agent-workflow/pattern_notes/` (see
`PATTERN_NOTE_TEMPLATE.md`) describing the reusable shape — real MPT/receipt
inclusion proof construction and verification against a chain-fetched root —
so the Aptos ticket can reuse it instead of rediscovering the same fix
independently.
