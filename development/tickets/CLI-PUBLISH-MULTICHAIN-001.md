---
id: CLI-PUBLISH-MULTICHAIN-001
title: "Signed ownership proof publish only implemented for Bitcoin"
theme: "multichain sanad create/publish UX"
crate: csv-cli
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/sanads.rs"
target_patterns:
  - "let proof_bytes = if chain.as_str() == \"bitcoin\""
  - "ownership-proof signing is"
  - "not implemented for this chain. Only 'bitcoin' is supported"
interface_files:
  - "csv-keys/src/bip44.rs"
  - "csv-protocol/src/signature.rs"
  - "csv-cli/src/wallet_identity.rs"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli --all-features"
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
cross_boundary_check: true
---

## Problem

`csv sanad create` (the `csv-cli/src/commands/sanads.rs::cmd_create` command
that produces a published, canonical/Active Sanad with a signed ownership
proof) only implements ownership-proof signing for Bitcoin
(`sanads.rs:1075-1105`):

```rust
let proof_bytes = if chain.as_str() == "bitcoin" {
    // Derive the BIP-86 path for the account/index
    let path = csv_keys::bip44::DerivationPath::new_bip86(account, index);
    let secret_key = csv_keys::bip44::derive_key_from_path(&seed_array, &path, &core_chain)...?;
    // ... sign commitment.as_bytes() with secp256k1 ...
    Some(signature.serialize_compact().to_vec())
} else {
    // Fail closed: only Bitcoin has a real ownership-proof signing path
    // wired here. Emitting anything else (previously the raw wallet seed,
    // which leaked key material) would persist a forged proof labeled as a
    // valid signature. ...
    None
};
```

For every other chain, `proof_bytes` is `None`, and the publish path fails
closed (`sanads.rs:1156-1167`):

```rust
// Fail closed: never persist a published, Active sanad with an unsigned
// ownership proof. Only Bitcoin can currently produce a real signature
// above; other chains reach here with `proof_bytes == None`.
if proof_bytes.is_none() {
    return Err(anyhow::anyhow!(
        "Cannot publish a sanad on chain '{}': ownership-proof signing is \
         not implemented for this chain. Only 'bitcoin' is supported for \
         canonical (published) sanad creation at this time. Re-run with \
         --skip-publish to produce an unsigned local draft instead.",
        chain.as_str()
    ));
}
```

Ethereum, Solana, Sui, and Aptos users of `csv sanad create` cannot produce a
real published Sanad at all — they must pass `--skip-publish` and accept an
unsigned local draft.

The comment's mention of a prior version that emitted the raw wallet seed as
a forged proof is important context: the current `None` fallback is a
deliberate, correct fix for a past key-leak bug, not the original problem.
This ticket is about extending real signing to the other four chains, not
about removing the fail-closed guard.

## Why it matters

This is a real feature gap affecting Ethereum/Solana/Sui/Aptos users of the
publish flow. It fails closed today (no fabricated proof persisted as if
valid), which is correct per `.agents/AGENT.md §1.2` ("no placeholder
verification") and the existing in-code comment's own rationale — but it
blocks a documented CLI capability (`csv sanad create` without
`--skip-publish`) for 4 of 5 chains.

## Task

Extend the signed-ownership-proof publish path (the `if chain.as_str() ==
"bitcoin" { ... } else { None }` block at `sanads.rs:1075-1105`) to Ethereum,
Solana, Sui, and Aptos:

- For each chain, derive the owner's private key from the wallet seed using
  the appropriate `csv-keys::bip44` derivation (BIP-44/SLIP-10 path and
  chain ID, matching how `owner_address`/`account`/`index` are already
  derived elsewhere in this same command for that chain).
- Sign `commitment.as_bytes()` with the chain-appropriate scheme (secp256k1
  for Ethereum/Solana, ed25519 for Sui/Aptos — check each adapter's `ops.rs`
  for an existing "prove ownership" or equivalent signing helper to reuse
  before writing new signing code from scratch; none was found in the
  adapters at audit time, so this may need to be written using the same
  direct-crate-call pattern the Bitcoin branch uses).
- Ensure the resulting `proof_bytes`/`OwnershipProof` construction matches
  what each chain's verification path expects (check
  `csv_protocol::OwnershipProof` consumers per chain, and each adapter's
  ownership/signature verification, so a proof produced here actually
  verifies later).
- Preserve the existing fail-closed guard (`if proof_bytes.is_none() { ... }`)
  for any chain that still isn't wired up after this change — do not weaken
  it.

## Acceptance criteria

- [ ] `csv sanad create` (without `--skip-publish`) works for Ethereum,
      Solana, Sui, and Aptos, producing a real signed ownership proof, not
      just Bitcoin.
- [ ] Each chain's signed proof round-trips through this project's ownership
      verification path successfully.
- [ ] The fail-closed guard remains in place and is tested for any
      still-unimplemented chain (if any remain after this change).
- [ ] Test per chain (or a parametrized cross-chain test) covering signed
      publish for all five chains.
- [ ] Production code does not fall back to raw wallet seed bytes or any
      other fabricated proof for a chain that lacks a real signing path.
- [ ] All `verify_commands` pass.

## Notes

The command name is `csv sanad create` (not `csv sanad publish` — there is no
separate `publish` subcommand; publishing is the default behavior of `create`
unless `--skip-publish` is passed).
