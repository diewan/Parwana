---
id: A-SUI-MINT-001
title: "Replace Sui mint_sanad zero placeholders with derived source commitment data"
theme: A
crate: csv-adapters/csv-sui
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-sui/src/ops.rs
target_patterns:
  - "let sanad_id = SanadId::new([0u8; 32]); // Placeholder - should derive from source"
  - "let commitment = Hash::new([0u8; 32]); // Placeholder - should derive from lock_proof"
  - "state: 1, // Created (placeholder)"
interface_files:
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-protocol/src/sanad.rs
  - csv-adapters/csv-sui/src/mint.rs
reference_crate: csv-adapters/csv-ethereum
reference_file: csv-adapters/csv-ethereum/src/ops.rs
reference_patterns:
  - "async fn mint_sanad("
  - "let calldata = call.abi_encode();"
verify_commands:
  - "cargo check -p csv-sui"
  - "cargo test -p csv-sui"
---

## Problem

Sui minting currently fabricates the destination `SanadId` and commitment using zero hashes, then reports a generic created state. That is fabricated blockchain/protocol state in a mint path.

## Why it matters

The adapter rules prohibit fabricated state and minting without verified source proof data. A destination mint must be tied to the source sanad, source seal, lock proof, and verified commitment data.

## Task

Replace the zero-placeholder `SanadId`, commitment, and source seal construction in Sui `mint_sanad` with values deterministically derived from the verified `lock_proof` and source transfer material. The implementation must fail closed if the proof is missing or malformed. Update state reading so it parses real on-chain state fields where available, or returns a typed error if the Sui object format cannot prove the requested state.

## Acceptance criteria

- [ ] No `[0u8; 32]` placeholder remains in the Sui mint path for sanad ID, commitment, or source seal.
- [ ] Malformed/short lock proofs return `Err(...)`, never a default commitment.
- [ ] Destination mint data is deterministic and tied to source proof material.
- [ ] Positive test covers valid proof-derived mint parameters.
- [ ] Negative test rejects empty/malformed proof bytes.
- [ ] `cargo check -p csv-sui` passes.
- [ ] `cargo test -p csv-sui` passes.

## Notes

If the current Sui RPC/SDK types do not expose enough data, do not fake it. Return a typed capability/configuration error and document the missing field.
