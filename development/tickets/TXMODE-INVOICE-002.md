---
id: TXMODE-INVOICE-002
title: "Adapter-backed invoice seal-ownership check for Sui, Ethereum, and Solana"
theme: interactive-transfer-invoice-ownership
crate: csv-cli
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: .agents/AGENT.md
target_file: csv-cli/src/commands/cross_chain/transfer.rs
target_patterns:
  - "fn verify_seal_controlled"
  - "fn parse_seal_ref"
  - "Offline ownership verification is not available"
target_file_2: csv-wire/src/seal.rs
target_patterns_2:
  - "pub enum SealDefinition"
  - "SEAL_ID32_LEN"
interface_files:
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-protocol/src/seal_protocol.rs
  - csv-sdk/src/lib.rs
reference_crate: csv-cli
reference_file: csv-cli/src/commands/cross_chain/transfer.rs
reference_patterns:
  - "SealDefinition::Bitcoin"
  - "SealDefinition::Aptos"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo build -p csv-wire -p csv-runtime -p csv-sdk -p csv-cli"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli cross_chain::"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-wire seal"
  - "cargo clippy -p csv-cli -p csv-wire --all-features -- -D warnings"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "Ok(()) // Placeholder"
  - "Ok(true) // Placeholder"
  - "assume owned"
  - "// TODO: verify"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

The interactive-transfer `invoice` command proves the recipient controls the
destination seal **offline** before issuing an invoice. Today only two chains are
provable, and the other three fail closed:

- `csv-cli/.../transfer.rs` — `verify_seal_controlled` returns an error for
  `SealDefinition::Sui { .. } | SealDefinition::Ethereum { .. }`:

  > "Offline ownership verification is not available for {} seals: control of an
  > object/storage slot cannot be derived from wallet key material without an
  > on-chain query. This fail-closed path will be lifted by a follow-up adding an
  > adapter-backed ownership check; use a Bitcoin or Aptos destination seal for now."

- **Solana cannot even be named as a destination seal.** `csv-wire`'s
  `SealDefinition` enum has only `Bitcoin | Sui | Aptos | Ethereum` variants, and
  the CLI's `parse_seal_ref` has no `solana:` branch, so a Solana invoice is
  rejected at parse time with "Unsupported seal chain".

The result: the `send`/`invoice`/`accept` flow only works end-to-end with a
Bitcoin or Aptos destination, even though the send-transition *signing* path
(`sign_send_transition`) and `seal_strength_rank` already support all five chains.
Note strength and offline-provability are independent axes: Sui is the *strongest*
seal (rank 4, tied with Bitcoin) yet is unprovable offline precisely because its
single-use guarantee lives in network-assigned on-chain object state.

## Why it matters

`invoice` is the grief-proofing step: because the recipient defines the seal, a
sender can only ever assign the sanad to a seal the recipient owns. If we issued
an invoice for a seal the recipient does *not* control, a sender could burn the
source sanad into a destination the recipient can never spend — an
irrecoverable-loss bug. So the ownership check MUST stay **fail-closed**: it may
only pass on a positive, adapter-confirmed ownership result, never on "couldn't
check" or "assume owned" (`.agents/AGENT.md`: no placeholder verification, no
fabricated blockchain state).

Sui object ownership and Ethereum storage-slot / Solana account control are not
derivable from wallet key material — they require a live chain query. The check
therefore has to move from a pure-offline derivation to an adapter-backed query,
**without violating the CLI layering rule**: `csv-cli` holds no protocol authority
and must NOT import chain adapters. The query has to be dispatched through
`csv-runtime` / `csv-sdk` (coordinator + adapter registry), exactly like every
other chain interaction.

## Task

Lift the fail-closed branch so a recipient can issue an invoice for a Sui,
Ethereum, or Solana destination seal, gated on a **positive** adapter-backed
ownership confirmation. Concretely:

1. **`csv-wire` (`seal.rs`)** — add a `SealDefinition::Solana` variant with a
   pinned `SealPoint` encoding (follow the existing per-variant doc + length-
   validated constructor pattern; document the `id`/`version` layout in the
   enum-level mapping comment). A Solana single-use seal is an account/PDA the
   recipient controls — pin `id = pubkey(32)` (state the exact layout you choose
   in the doc comment) and add a `SealDefinition::solana(..)` constructor plus a
   `to_seal_point` arm. Update `SEAL_ID32_LEN` usage/tests accordingly.

2. **Adapter-backed ownership query (runtime/SDK + adapters)** — expose one entry
   point on `csv-sdk` (backed by `csv-runtime` dispatch through the coordinator +
   adapter registry) that answers: *does address/key `A` control seal
   `SealDefinition` on chain `C`?* Implement the per-chain check in the Sui,
   Ethereum, and Solana adapters:
   - **Sui** — fetch the object by id; confirm `owner == wallet Sui address` and
     the object exists at (or the invoice pins) the given `version`.
   - **Ethereum** — confirm control of the `(contract, slot)` per the CSVSeal
     registry's ownership semantics (e.g. `eth_getStorageAt` / the registry's
     owner mapping resolves to the wallet address). Do not treat a zero/absent
     slot as owned.
   - **Solana** — fetch the account; confirm the wallet is the account's
     owner/authority per the seal program's semantics.

3. **`csv-cli` (`transfer.rs`)** — add a `solana:` branch to `parse_seal_ref`; in
   `verify_seal_controlled`, keep the Bitcoin/Aptos **offline** fast path
   unchanged, and for Sui/Ethereum/Solana call the new SDK ownership check.
   Preserve fail-closed: any RPC error, ambiguous result, or negative answer
   returns an error and no invoice is issued. Because this path now needs RPC for
   those three chains, thread the destination-chain RPC config through (mirror how
   `build_client` resolves `config.chain(to)`), and surface a clear error if the
   destination chain has no configured RPC.

Keep the change scoped to the files above plus the three adapters' ownership
implementations. Do not alter the Bitcoin/Aptos offline behavior.

## Acceptance criteria

- [ ] `SealDefinition::Solana` exists in `csv-wire` with a documented pinned
      `SealPoint` encoding, a length-validated constructor, and a `to_seal_point`
      arm; round-trip + rejects-wrong-length tests added.
- [ ] `parse_seal_ref` accepts `solana:<...>:<...>` and rejects malformed input;
      the error message lists solana among supported chains.
- [ ] `verify_seal_controlled` passes ONLY on a positive adapter-confirmed
      ownership result for Sui, Ethereum, and Solana; RPC error / not-found /
      wrong-owner / wrong-version all fail closed with an actionable message.
- [ ] The ownership query is dispatched through `csv-sdk`/`csv-runtime`; `csv-cli`
      adds no direct `csv-adapters/*` dependency (architecture-compliance test
      still passes).
- [ ] Bitcoin and Aptos invoice issuance remain offline (no new RPC round-trip)
      and behaviorally unchanged.
- [ ] Positive test per chain (owned seal ⇒ invoice issued) and negative/
      adversarial test per chain (not-owned / wrong-owner / RPC-down ⇒ fail
      closed, no invoice).
- [ ] Production code introduces no `todo!`, `unimplemented!`, `unwrap`/`expect`
      on fallible RPC, fabricated ownership results, or silent "assume owned"
      fallback.
- [ ] All `verify_commands` pass.
- [ ] Repo-wide grep confirms no remaining "Offline ownership verification is not
      available" fail-closed stub for these three chains.

## Notes

- **Layering is a hard constraint, not a preference.** `csv-cli` must reach the
  adapters only through `csv-runtime`/`csv-sdk`. If the cleanest shape is a new
  trait method, add it on the seal/chain-adapter trait in `csv-protocol` and
  implement it in each adapter; the CLI calls the SDK wrapper.
- **Do not guess the CSVSeal ownership semantics** for Ethereum's storage slot or
  Solana's account model. If the registry contract's notion of "the recipient
  controls this slot/account" is not unambiguous from the contract sources under
  `csv-contracts/{ethereum,solana}/`, stop and record the open question here
  rather than inventing a check — a wrong check that passes is worse than the
  current fail-closed.
- This ticket may be split into `TXMODE-INVOICE-002-{SUI,ETH,SOL}` if the single
  scope proves too large per the one-ticket-one-context-pack workflow; the Solana
  slice carries the extra `csv-wire` variant prerequisite and should land first if
  split.
- Related history: [[txmode-invoice-001]] (the offline invoice CLI that
  introduced this fail-closed branch), [[txmode-model-001-invoice-data-model]]
  (the `SealDefinition`/`Invoice` data model), [[seal-strength-ordering]]
  (strength ≠ offline-provability).
