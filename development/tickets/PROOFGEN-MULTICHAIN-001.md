---
id: PROOFGEN-MULTICHAIN-001
title: "Real multi-chain proof generation for `proof generate` and off-chain `send` (Ethereum, Aptos, Sui, Solana)"
theme: proof-generation-multichain
crate: csv-sdk
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: .agents/AGENT.md
target_file: csv-sdk/src/runtime.rs
target_patterns:
  - "pub async fn generate_proof"
  - "resolve_sanad_anchor"
  - "build_inclusion_proof"
target_file_2: csv-cli/src/commands/proofs.rs
target_patterns_2:
  - "chain_runtime()"
  - "generate_proof"
interface_files:
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-adapters/csv-adapter-core/src/lib.rs
  - csv-adapters/csv-ethereum/src/runtime_adapter.rs
  - csv-adapters/csv-aptos/src/runtime_adapter.rs
reference_crate: csv-bitcoin
reference_file: csv-adapters/csv-bitcoin/src/ops.rs
reference_patterns:
  - "resolve_sanad_anchor"
  - "SanadAnchorLocation"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo build -p csv-sdk -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-sdk"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-ethereum -p csv-aptos -p csv-sui -p csv-solana build_inclusion_proof"
  - "cargo clippy -p csv-sdk -p csv-cli --all-features -- -D warnings"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "fabricate"
  - "Ok(true) // Placeholder"
  - "serialize the block" 
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

`ChainRuntime::generate_proof` (`csv-sdk/src/runtime.rs`) is the shared entry point
behind both the `csv proof generate` CLI verb (`csv-cli/.../proofs.rs`) and the
interactive off-chain `csv cross-chain send` proof step. After PROOFGEN-BTC (the
`resolve_sanad_anchor` fix) it produces a real inclusion + finality proof **only
for Bitcoin**. For every other chain this legacy path does not produce a usable
proof:

- **Ethereum, Aptos** — their `ops.rs` `ChainProofProvider::build_inclusion_proof`
  is deliberately DISABLED and fails closed with `CapabilityUnavailable`
  ("Legacy … inclusion proofs are disabled … Use the runtime ChainProofPort
  path"). They return `None` from `resolve_sanad_anchor`, so `generate_proof`
  fails closed.
- **Sui** — `ops.rs` `build_inclusion_proof` treats `anchor_id` as a transaction
  digest; `generate_proof` supplies the 32-byte sanad id, which is not a digest,
  so the RPC lookup returns not-found.
- **Solana** — `ops.rs` `build_inclusion_proof` requires a 64-byte transaction
  signature; the 32-byte sanad id fails the length check.

The real, non-fabricating proof path already exists for the lock/materialize flow:
`csv_adapter_core::ChainProofPort::build_inclusion_proof` (built from finalized
transaction receipts / accumulator evidence, see each adapter's
`runtime_adapter.rs`). The legacy `generate_proof` path is simply not wired to it.

**User-visible impact:** tutorials that show `csv proof generate --chain ethereum
<SANAD_ID>` (`csv-examples/cli-tutorial/quick-start.sh`,
`cross-chain-transfer.sh`, `csv-cli-tutorial.md`) demonstrate a step that fails
closed today, and interactive off-chain `send` only works with a Bitcoin source.

## Why it matters

Proof generation is protocol-critical: a proof bundle is what a recipient
client-side-validates on `accept`, and what authorizes a cross-chain mint. The
`.agents/AGENT.md` rules forbid fabricated blockchain state, placeholder
verification, and proofs not backed by real inclusion + finality. The **failure
mode here is safe** (fail-closed, no fabrication) — this ticket is about closing
the capability gap correctly, NOT about relaxing any check. Whatever lands must
keep producing only receipt/accumulator-backed inclusion evidence and real
finality evidence; it must never resurrect the fabricated event-payload paths
these `ops.rs` methods were disabled to remove.

## Task

Make `proof generate` and off-chain `send` produce real proofs for Ethereum,
Aptos, Sui, and Solana, using the same evidence the coordinator/lock path already
trusts. Pick ONE of these approaches (see Notes for the recommendation) and apply
it uniformly:

- **(A, recommended) Route the legacy path through `ChainProofPort`.** Have
  `generate_proof` (or the CLI verbs directly) resolve the sanad's anchor
  transaction and build the bundle via the runtime `ChainProofPort` /
  `adapter_registry` path that `runtime_adapter.rs` already implements, instead of
  the disabled/naive `ChainProofProvider` in `ops.rs`. This reuses the audited,
  receipt-backed logic and deletes the divergence between "fresh" and
  "lock/resume" proof generation.

- **(B) Implement `resolve_sanad_anchor` + real `ops.rs build_inclusion_proof`
  per chain** (mirroring the Bitcoin fix), so the existing `generate_proof` shape
  works. Only choose this if (A) is not feasible; it risks re-duplicating logic
  that already lives in `runtime_adapter.rs`.

Either way, resolve the sanad's real on-chain anchor (tx hash + confirming
block/version/slot) per chain — never the sanad id or the chain tip — and fail
closed with a clear, actionable error when the anchor is unconfirmed or the sanad
is unknown.

## Acceptance criteria

- [ ] `csv proof generate --chain <ethereum|aptos|sui|solana> <SANAD_ID>` produces
      a proof bundle backed by real inclusion + finality evidence for a confirmed
      sanad, and fails closed (clear message) when unconfirmed/unknown.
- [ ] Interactive off-chain `csv cross-chain send --from <non-bitcoin>` builds a
      valid consignment whose bundle passes `csv_verifier::verify_proof_bound` on
      `accept` (seal binding, domain separation `anchor_id == sanad_id`, freshness).
- [ ] No fabricated event payloads or synthetic block hashes are reintroduced; the
      disabled `ops.rs` inclusion paths are not silently re-enabled with fake data.
- [ ] Bitcoin behavior is unchanged (regression guard).
- [ ] Per-chain positive test (confirmed sanad ⇒ real bundle) and negative test
      (unconfirmed/unknown ⇒ fail closed) added.
- [ ] `csv-cli` gains no direct `csv-adapters/*` dependency; multi-chain proof
      building stays behind `csv-sdk`/`csv-runtime` (architecture-compliance test
      still passes).
- [ ] All `verify_commands` pass; `cargo clippy` clean.
- [ ] Tutorials updated to match reality: the `proof generate --chain ethereum`
      steps in `quick-start.sh`, `cross-chain-transfer.sh`, and
      `csv-cli-tutorial.md` either work end-to-end after this change or are
      corrected/removed.

## Notes

- **Recommendation: approach (A).** The Ethereum and Aptos `ops.rs` methods
  explicitly redirect to "the runtime ChainProofPort path", and
  `csv_adapter_core::ChainProofPort::build_inclusion_proof` + `tx_finality`
  already build receipt/accumulator-backed evidence for the lock flow. Unifying
  onto it avoids maintaining two proof builders per chain and removes the
  fresh-vs-resume drift noted across prior audits.
- The Bitcoin fix added the reusable seam `ChainProofProvider::resolve_sanad_anchor`
  (+ `SanadAnchorLocation`) in `csv-protocol` and `BitcoinRpc::get_tx_block_height`.
  If (B) is chosen, follow that shape; if (A) is chosen, `resolve_sanad_anchor` may
  remain Bitcoin-only and the non-Bitcoin resolution lives on the `ChainProofPort`
  side.
- **Do not guess anchor semantics.** The sanad -> anchor-transaction mapping for
  each chain (ETH lock/receipt tx, Aptos tx version, Sui object version/digest,
  Solana signature/slot) must come from real adapter state, not be inferred. If a
  chain has no reliable local mapping for a freshly created (not-yet-locked)
  sanad, record that as an open question here rather than inventing one.
- Related history: [[generate-proof-anchor-resolution]] (the Bitcoin fix and the
  per-chain status this ticket generalizes), [[resumability-audit-per-chain]],
  [[transfer-finality-dual-driver]].
