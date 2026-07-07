---
id: MINT-KEYS-001
title: "Production mint verifier key management"
theme: "thin-registry mint operations"
crate: "csv-adapter-factory"
priority: P1
security_critical: true
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapter-factory/src/lib.rs"
target_patterns:
  - "pub const MINT_VERIFIER_KEY_ENV"
  - "pub(crate) fn load_mint_verifier_key"
target_file_2: "csv-cli/src/commands/cross_chain/transfer.rs"
target_patterns_2:
  - "ensure_destination_attestor_ready"
  - "CSV_MINT_VERIFIER_KEY"
interface_files:
  - "csv-adapter-factory/src/aptos.rs"
  - "csv-adapter-factory/src/sui.rs"
  - "csv-adapter-factory/src/solana.rs"
  - "csv-runtime/src/transfer_coordinator.rs"
  - "csv-protocol/src/chain_adapter_traits.rs"
reference_crate: "csv-adapter-factory"
reference_file: "csv-adapter-factory/src/lib.rs"
reference_patterns:
  - "load_mint_verifier_key"
  - "MINT_VERIFIER_KEY_ENV"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-adapter-factory --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-runtime --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-adapter-factory --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli cross_chain:: --all-features"
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
contract_files:
  - "csv-contracts/aptos/contracts/sources/csv_seal.move"
  - "csv-contracts/sui/contracts"
  - "csv-contracts/solana/contracts"
cross_boundary_check: true
---

## Problem

The current materialize path uses one process-wide environment variable,
`CSV_MINT_VERIFIER_KEY`, for RFC-0012 thin-registry mint attestations. That is
acceptable for testnet and single-destination CLI runs, but it is not a
production key-management model.

Production operators need:

- different verifier signing keys per environment;
- different verifier signing keys per destination chain;
- multiple verifier keys for a single destination chain;
- threshold signing, for example 2-of-3, where the destination registry requires
  more than one verifier signature;
- an HSM/KMS-backed signer path so raw production verifier keys are not stored
  in `.env`, shell history, config files, or process listings.

Today the adapter factory can only load one raw secp256k1 private key from
`CSV_MINT_VERIFIER_KEY`, and the CLI preflight only checks that this one env var
is present for Sui/Aptos/Solana materialization.

## Why it matters

The mint verifier key authorizes destination-chain materialization. Reusing one
raw key across all chains and environments creates an unnecessarily large blast
radius: compromise of one runtime process or testnet secret could affect every
destination chain that trusts the same public key.

This is security-critical because the runtime signs the destination mint digest
that the thin registry verifies on-chain. The implementation must preserve these
invariants:

- no destination mint without a verifier signature that matches the destination
  registry's configured verifier set;
- no silent fallback from a missing chain-specific signer to an unrelated signer;
- no placeholder signatures, zero keys, fake attestations, or fabricated
  threshold satisfaction;
- no private key material in logs, receipts, config output, or error strings.

## Task

Introduce a production-ready mint verifier signer configuration and selection
layer.

The signer layer should choose signer material by destination chain and support
multiple signers per chain. It should preserve the existing
`CSV_MINT_VERIFIER_KEY` behavior as a backwards-compatible testnet/default path,
but production configuration should prefer chain-scoped and provider-backed
signers.

Suggested environment-variable compatibility:

- `CSV_MINT_VERIFIER_KEY` remains the legacy/default single-key path.
- `CSV_MINT_VERIFIER_KEY_APTOS`
- `CSV_MINT_VERIFIER_KEY_SUI`
- `CSV_MINT_VERIFIER_KEY_SOLANA`

For multiple local test signers, use a clearly documented format such as a
comma-separated list of 32-byte hex private keys. For production, prefer a
provider abstraction rather than raw env vars:

```rust
pub trait MintAttestationSigner {
    fn signer_id(&self) -> String;
    fn public_key(&self) -> Result<Vec<u8>, SignerError>;
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SignerError>;
}
```

This shape is illustrative. Prefer existing protocol/runtime signing traits if
they fit.

## Scope

In scope:

- destination-chain-specific signer selection;
- multiple signers per destination chain;
- explicit threshold-aware signature collection or a clear interface that
  returns all locally available signatures for runtime aggregation;
- CLI preflight that checks the signer selected for the requested destination
  chain, not only `CSV_MINT_VERIFIER_KEY`;
- tests for missing signer, wrong-chain signer, multiple signers, and legacy
  single-key compatibility;
- documentation updates to the mint verifier runbooks.

Out of scope:

- changing the on-chain verifier-set model unless a chain contract cannot
  already support multiple verifiers and thresholds;
- committing any private key material;
- making the CLI authoritative for verifier sets. On-chain registry state
  remains authoritative.

## Acceptance criteria

- [ ] The adapter factory resolves mint verifier signers by destination chain.
- [ ] `CSV_MINT_VERIFIER_KEY` continues to work as a legacy/default path for
      local testnet operation.
- [ ] Chain-scoped keys, for example `CSV_MINT_VERIFIER_KEY_APTOS`, override the
      legacy/default key only for that destination chain.
- [ ] A missing signer for a destination chain fails closed before the source
      Sanad is locked.
- [ ] A signer configured for one destination chain is not silently reused for a
      different destination chain unless the operator explicitly configured a
      default/fallback key.
- [ ] Multiple local signers for one chain can be loaded and attached without
      leaking private material.
- [ ] Runtime or adapter mint code can produce multiple verifier signatures when
      multiple local signers are configured.
- [ ] HSM/KMS-backed signer support is represented by an interface and at least
      one stub-free provider implementation or fail-closed provider scaffold with
      clear errors.
- [ ] CLI error messages name the missing destination-chain signer requirement
      without printing key material.
- [ ] Runbooks document production recommendations: environment separation,
      chain separation, threshold signing, rotation, and KMS/HSM storage.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, zero-key placeholders, fake signatures, or silent fallbacks.
- [ ] Positive tests cover legacy key, chain-scoped key, and multiple signers.
- [ ] Negative tests cover missing destination signer and wrong-chain signer.
- [ ] All `verify_commands` pass.

## Notes

Recommended production posture:

- production keys must differ from testnet/dev keys;
- destination chains should have separate verifier key sets unless there is a
  documented operational reason to share a key;
- high-value destinations should use threshold > 1 where chain contracts and
  operations support it;
- private keys should live in HSM/KMS-backed signing services, not long-lived
  shell environment variables;
- verifier rotation should add the new public key, update runtimes, adjust
  threshold if needed, then remove the old key after all signers are healthy.

The committed deployment manifest records verifier public keys and thresholds
for auditability, but it must never carry private keys.
