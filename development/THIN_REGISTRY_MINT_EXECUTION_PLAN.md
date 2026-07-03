# Thin Registry Mint Execution Plan

## Purpose

This document is the execution plan for [`RFC-0012: Thin Registry Cross-Chain Mint`](../rfcs/RFC-0012-thin-registry-cross-chain-mint.md).

The RFC decides the protocol model. This document defines how to carry that decision through design, implementation, deployment, and validation.

## Scope

This plan covers:

- contract redesign for Ethereum, Solana, Sui, and Aptos destination mint paths
- runtime, binding, and adapter alignment
- operator flow for mint submission
- source-chain escrow and settlement
- end-to-end validation, deployment, and hardening

Bitcoin is part of the source-chain and proof-production side of the flow, but does not require a destination smart contract.

## Non-Goals

This plan does not include:

- a full on-chain SPV implementation
- a migration of `ProofLeafV1` from `u8` chain IDs to `bytes32`
- protocol redesign outside destination mint, replay anchoring, and settlement

## Critical Design Constraint

Thin registry does not mean unauthenticated mint.

If a destination contract only checks:

- `sanadId` uniqueness
- `nullifier` uniqueness
- `lockEventId` uniqueness

then any caller could mint arbitrary records unless the contract also has an authorization mechanism for who is allowed to register a verified mint.

Therefore Phase 1 MUST choose and freeze one canonical mint authorization model before contract work is considered complete.

### Decision (frozen)

The authorization model is **verifier-signed mint attestation**, per [RFC-0012 §9](../rfcs/RFC-0012-thin-registry-cross-chain-mint.md). The alternative — an authorized-caller (`msg.sender`) allowlist — is rejected because it couples authority to the transaction submitter and forces per-chain governance for operator rotation, which contradicts the proof-carrying model.

Consequences that flow from this decision and bind every later phase:

- The mint calldata carries `bytes[] verifierSignatures` over the canonical SHA-256 / secp256k1 attestation digest (RFC §9.2).
- The digest MUST bind `destinationChainId` and `destinationContract` to prevent cross-chain and redeploy replay.
- Each contract stores a verifier set + threshold `M`; `M = 1` is allowed for the ETH fast-track, `M`-of-`N` requires no ABI change.
- Escrow release is authorized by a verifier-signed `SettlementReceipt`, not by the operator (RFC §10), because the operator is the payout beneficiary and must not self-deal.
- Where a contract already has an immutable `verifier` (Ethereum `CSVSeal`), generalize it into the verifier set; do not introduce a parallel trust primitive.

## Success Criteria

The program is complete when all of the following are true:

- destination mint no longer depends on proof-root installation or timelocked root updates
- all destination chains use equivalent thin-registry mint semantics
- runtime verification remains off-chain and authoritative
- adapters and bindings use the new mint ABI consistently
- operator-submitted destination mint succeeds end-to-end
- source-chain escrow releases on confirmed destination mint
- BTC -> ETH completes end-to-end on testnet
- the same architecture generalizes to Solana, Sui, and Aptos

## Phase Overview

1. Phase 0: Constitution and spec alignment
2. Phase 1: Canonical mint authorization and settlement spec
3. Phase 2: Uniform thin-registry contract redesign
4. Phase 3: Runtime, binding, and adapter alignment
5. Phase 4: ETH fast-track and manual operator flow
6. Phase 5: Escrow settlement automation
7. Phase 6: Multi-chain rollout
8. Phase 7: End-to-end hardening and release readiness

## Phase 0: Constitution and Spec Alignment

### Goal

Make the protocol and contract documents internally consistent with RFC-0012.

### Work

- update `RFC-0006` to remove destination-mint proof-root anchoring as the canonical model
- update [ABI_CONSTITUTION.md](./ABI_CONSTITUTION.md) to describe thin-registry mint semantics
- update [CANONICAL_EVENT_SCHEMA.md](./CANONICAL_EVENT_SCHEMA.md) so mint and settlement events reflect the new model
- identify every document that still implies proof-root-gated destination mint
- define the normative field names and meanings for:
  - `sanadId`
  - `commitment`
  - `sourceChain`
  - `destinationOwner`
  - `lockEventId`
  - `nullifier`

### Deliverables

- revised contract constitution docs
- canonical field dictionary for thin-registry mint
- explicit deprecation note for proof-root-gated destination mint

### Exit Criteria

- no contract-facing doc describes proof-root installation as required for ordinary mint
- all chain teams can implement from one spec without inferring missing semantics

### Risks

- semantic drift between RFC-0012 and older contract docs
- inconsistent event names or field meanings across chains

## Phase 1: Canonical Mint Authorization and Settlement Spec

### Goal

Freeze the two pieces RFC-0012 intentionally left open:

- who is allowed to register a verified mint
- what minimal proof of destination mint releases source-chain escrow

### Work

- authorization model is already frozen to verifier-signed attestation (see Decision above / RFC §9); the remaining Phase 1 work is to pin its parameters:
- pin the canonical attestation digest byte layout and confirm it matches RFC §9.2 exactly (domain tag, field order, `destinationChainId` + `destinationContract` binding, `attestationExpiry`)
- pin the signature scheme parameters: SHA-256 digest, secp256k1, and the per-chain native verify primitive and stored verifier-identity form (EVM address vs. 33-byte compressed pubkey)
- define initial threshold `M`, verifier-set membership, and rotation/revocation policy per chain
- define anti-replay domain for authorization payloads (`sanadId` + `nullifier` + `lockEventId` uniqueness on-chain; `destinationChainId` + `destinationContract` + `attestationExpiry` in the digest)
- confirm settlement receipt format against RFC §10; pin the canonical form of `destinationContract` and `destinationMintTxRef` on non-EVM chains
- define whether settlement receipt is:
  - destination tx hash plus event proof
  - destination event digest plus operator attestation
  - destination-chain native receipt or inclusion proof
- define failure handling:
  - operator paid gas but mint reverted
  - mint succeeded but settlement receipt delayed
  - duplicate settlement submission
  - source-chain reorg before final settlement

### Deliverables

- mint authorization spec
- settlement receipt spec
- threat analysis for forged mint and forged settlement

### Exit Criteria

- a contract can reject unauthorized mint registration
- a source escrow contract can verify exactly one successful settlement path
- replay domains are explicit for mint authorization and settlement

### Risks

- under-specifying authorization and accidentally creating a permissionless mint registry
- over-engineering settlement receipt to the point that it recreates a proof-root system

### Decision Gate

Phase 2 MUST NOT start final contract ABI freeze until this phase is closed.

## Phase 2: Uniform Thin-Registry Contract Redesign

### Goal

Redesign all destination contracts around the same thin-registry mint semantics.

### Work

- define canonical storage layout for:
  - minted sanads
  - used nullifiers
  - recorded lock events
  - settlement status
  - operator or verifier authorization state
- define canonical mint entrypoint semantics
- remove proof-root-gated ordinary mint requirements
- keep optional proof-hash or leaf-hash helpers only as non-authoritative utilities
- define canonical refund and settlement state transitions
- define upgrade and deployment assumptions per chain

### Chain-Specific Work

#### Ethereum

- replace proof-root-gated `mint_sanad` semantics with thin-registry semantics
  - concretely: `_mint_sanad_internal` currently opens with `if (proofRoot != trustedProofRoot) revert InvalidProofRoot();` against a `trustedProofRoot` that is `0` at deploy and only movable through a 7-day timelock — this bricks mint on a fresh deploy and MUST be removed, not softened
  - the new entrypoint verifies `bytes[] verifierSignatures` over the RFC §9.2 digest, then checks `sanadId`/`nullifier`/`lockEventId` uniqueness, records, and emits
- generalize the existing immutable `verifier` into the verifier set + threshold `M`; keep verifier-set rotation behind the owner/timelock but OFF the mint path
- fold nullifier registration into the authenticated mint and remove or gate the standalone permissionless `register_nullifier` (today anyone can pre-register a nullifier and grief a future mint)
- retire the proof-root / governance-epoch subsystem (`trustedProofRoot`, `schedule/execute_proof_root_update`, `GovernanceEpoch`, `advance_epoch`) from the mint path; keep only a minimal owner/timelock scoped to verifier-set management
- treat `hashProofLeafV1` / merkle helpers as non-authoritative utilities only — note the on-chain `ProofLeafV1` encodes chain identity as `bytes32` while the Rust MCE uses `u8`, so it must not gate mint until reconciled
- define event topics and indexed fields for efficient settlement lookup; emit full `destinationOwner` bytes while storing `keccak256(destinationOwner)`

#### Solana

- redesign Anchor instruction shape for thin-registry mint
- define PDA layout for minted sanads, nullifiers, and lock events
- define signer expectations for operator or verifier authorization

#### Sui

- redesign Move entry function and object/state layout
- define event emission and uniqueness checks for object-based state
- define package-level authority model for operator or verifier approval

#### Aptos

- redesign Move entry function and resource layout
- define table keys for sanad minting, nullifier registration, and lock-event recording
- define signer and authorization path

### Deliverables

- finalized contract ABI per chain
- equivalent state machine semantics across chains
- canonical event set for mint and settlement

### Exit Criteria

- each destination chain has a contract spec that is equivalent at the semantic level
- no destination contract requires `trustedProofRoot`, `proofRoot`, or `leafPosition` for ordinary mint
- authorization is built into the mint path

### Risks

- chain-specific data-model differences causing semantic drift
- retaining legacy proof-root fields “temporarily” and never actually removing them

## Phase 3: Runtime, Binding, and Adapter Alignment

### Goal

Make the runtime and all adapters speak the new contract model without changing the verifier’s off-chain role.

### Work

- regenerate all contract bindings from finalized ABIs
- update runtime-facing mint request structures if needed
- update destination adapter mint builders to the new ABI
- update chain identity mapping:
  - contract layer uses `keccak256("csv.chain.<name>")`
  - `ProofLeafV1` stays unchanged
- remove legacy proof-root assumptions from adapter call builders
- remove dead or superseded manual encoders
- ensure off-chain verification still occurs before mint submission

### Adapter-Specific Checklist

#### Ethereum

- the current `csv-adapters/csv-ethereum/src/bindings/csv_seal.rs` describes a contract that no longer exists: it declares `uint8` chain IDs and camelCase `mintSanad(uint8 sourceChain, ...)` (binding `VERSION = 3`) while the deployed `.sol` is `VERSION = 5`, `bytes32` chain IDs, snake_case `mint_sanad`. Regenerate bindings from the finalized ABI; this stale binding is the source of the wrong-selector mint revert.
- fix selector and field layout to the new attestation-based ABI; `sourceChain = keccak256("csv.chain.<name>")`
- stop using block hash as `proofRoot` (drop `proofRoot` from the mint call entirely)
- remove stale hand-written encoder (`sanad_contract.rs` / `mint.rs`) after bindings are trusted
- have the adapter build the §9.2 digest and attach verifier signature(s); keep `validate_source_proof` as the off-chain gate that runs before the verifier signs

#### Solana

- wire the Anchor instruction builder to the new mint interface
- define the real mint authority signer path
- stop treating old proof-root-era instruction layout as canonical

#### Sui

- align Move call builder and runtime adapter with the new mint shape
- ensure source-chain and destination-owner encodings match spec

#### Aptos

- align entry-function payload shape with the new mint shape
- remove `u8` contract-chain assumptions from mint ABI where replaced by fixed-width identifiers

### Deliverables

- updated bindings
- updated adapter implementations
- removed dead legacy mint encoders and call builders

### Exit Criteria

- runtime mint submission uses one consistent semantic model across chains
- adapter code contains no proof-root-gated ordinary mint assumptions
- verifier remains the sole cross-chain proof adjudicator

### Risks

- silent ABI mismatch between generated bindings and actual deployed contracts
- accidental coupling between old `ProofLeafV1` chain encoding and new contract `sourceChain`

## Phase 4: ETH Fast-Track and Manual Operator Flow

### Goal

Unblock BTC -> ETH as the first live thin-registry path before automating escrow settlement.

### Work

- deploy the new Ethereum thin-registry contract
- update Ethereum chain config and address manifests
- stand up the mint operator path
- verify the operator can:
  - observe a verified transfer
  - submit destination mint
  - pay gas
  - record settlement evidence for later source release
- define operational runbook for retry, revert, and duplicate handling

### Deliverables

- deployed Ethereum thin-registry contract on testnet
- working manual operator flow for BTC -> ETH
- operator runbook

### Exit Criteria

- BTC lock can produce a verified proof bundle
- operator can mint on Ethereum under the new ABI
- mint result is observable and auditable from emitted events
- system can resume safely after interruption or retry

### Risks

- operator flow succeeds only manually but lacks enough observability for later automation
- Ethereum path is special-cased in ways that do not generalize

## Phase 5: Escrow Settlement Automation

### Goal

Automate the source-chain escrow release after confirmed destination mint.

### Work

- add source-chain lock-time escrow semantics
- implement settlement receipt submission on the source side
- the source escrow MUST authorize release on a verifier-signed `SettlementReceipt` (RFC §10), NOT on the operator's own claim — the operator is the beneficiary and must not be able to release its own payout
- verify receipt uniqueness and replay resistance (exactly one valid receipt per `lockEventId`)
- implement release-to-operator path; emit `SettlementReleased` distinct from `SanadMinted`
- implement refund or timeout path when destination mint never occurs
- integrate settlement status with runtime execution journal and recovery path

### Deliverables

- source-chain escrow contract or equivalent lock mechanism
- settlement receipt validation flow
- operator payout path
- timeout or refund flow

### Exit Criteria

- successful destination mint leads to exactly one escrow release
- failed or absent destination mint does not release escrow
- duplicate settlement attempts are rejected
- crash recovery can resume settlement safely

### Risks

- settlement proof too weak to justify release
- settlement proof too strong and expensive, recreating SPV-like complexity
- source and destination finality assumptions drift

## Phase 6: Multi-Chain Rollout

### Goal

Generalize the ETH path to Solana, Sui, and Aptos without changing the model.

### Work

- deploy thin-registry destination contracts on each chain
- update chain configs and deployment docs
- enable operator flows per chain
- run per-chain destination mint scenarios:
  - BTC -> Sui
  - BTC -> Aptos
  - BTC -> Solana
  - ETH -> Sui
  - Sui -> ETH
- compare emitted state and event semantics across chains

### Deliverables

- deployed destination contracts for all supported non-Bitcoin target chains
- chain-specific operator runbooks
- updated deployment and configuration docs

### Exit Criteria

- all supported destination chains expose the same mint semantics
- all chain adapters can participate in the thin-registry flow
- no chain requires the old proof-root mint path as fallback

### Risks

- one chain forces a semantic compromise that weakens uniformity
- operational tooling differs enough across chains that automation becomes fragmented

## Phase 7: End-to-End Hardening and Release Readiness

### Goal

Prove the architecture is safe, observable, and operationally stable before broader release.

### Work

- add unit, integration, and adversarial tests for:
  - duplicate sanad mint
  - duplicate nullifier
  - duplicate lock event
  - forged authorization payload
  - forged settlement receipt
  - retry after destination revert
  - resume after runtime crash during mint or settlement
- add conformance tests that compare chain-specific event/state semantics
- add metrics and logs for:
  - verified proof built
  - mint submitted
  - mint confirmed
  - settlement submitted
  - settlement confirmed
  - replay rejected
  - authorization rejected
- run full end-to-end matrix across supported chain pairs
- update operational docs and incident response runbooks

### Deliverables

- test coverage for mint, replay, authorization, and settlement
- observability coverage for operator flow
- release-readiness checklist

### Exit Criteria

- all critical replay and authorization tests pass
- crash recovery paths are validated
- all supported chain pairs complete end-to-end in test environments
- docs are sufficient for operator deployment without oral knowledge

### Risks

- happy-path success without sufficient adversarial coverage
- undocumented operator assumptions becoming hidden protocol dependencies

## Cross-Phase Workstreams

### Workstream A: Authorization

Must remain explicit in every phase:

- key ownership
- signature domain separation
- rotation
- revocation
- audit trail

### Workstream B: Replay and Identity

Must remain consistent in every phase:

- `sanadId` uniqueness domain
- `nullifier` derivation and scope
- `lockEventId` derivation and uniqueness
- `sourceChain` mapping between proof layer and contract layer

### Workstream C: Observability

Must exist before release:

- per-transfer traceability across source lock, proof verification, destination mint, and settlement
- event correlation IDs for runtime and operator logs
- operational alerts for stuck mint or settlement

### Workstream D: Recovery

Must be verified before release:

- safe retry after partial mint submission
- safe retry after settlement submission
- no duplicate mint or duplicate payout on crash recovery

## Validation Matrix

Each phase should close with validation at the appropriate layer.

### Document Validation

- RFCs and constitutions agree
- field names and semantics are consistent
- event schema matches contract plan

### Contract Validation

- no unauthorized mint registration
- duplicate sanad rejected
- duplicate nullifier rejected
- duplicate lock event rejected
- settlement release occurs exactly once

### Runtime Validation

- proof bundle still verified off-chain before mint
- mint request payload matches deployed ABI
- recovery resumes from incomplete mint and settlement phases

### End-to-End Validation

- BTC -> ETH with manual operator
- BTC -> ETH with automated settlement
- at least one additional destination chain beyond Ethereum

## Recommended Execution Order

If the priority is fastest unblock:

1. Phase 0
2. Phase 1
3. Ethereum slice of Phase 2
4. Ethereum slice of Phase 3
5. Phase 4
6. Phase 5
7. Remaining chains in Phase 6
8. Phase 7

If the priority is uniform multi-chain correctness first:

1. Phase 0
2. Phase 1
3. All-chain Phase 2
4. All-chain Phase 3
5. Phase 4 only as verification of the first deployed path
6. Phase 5
7. Phase 6
8. Phase 7

## Immediate Next Steps

The next concrete actions should be:

1. Update the older contract docs (`RFC-0006`, `ABI_CONSTITUTION.md`, `CANONICAL_EVENT_SCHEMA.md`) so they no longer contradict RFC-0012.
2. Pin the §9.2 attestation digest layout and §10 receipt layout as the frozen chain-agnostic ABI surface (the authorization model itself is already decided: verifier-signed attestation).
3. Freeze the chain-agnostic thin-registry ABI including `bytes[] verifierSignatures`.
4. Rewrite the Ethereum `mint_sanad` entrypoint to drop proof-root gating and verify the attestation, and regenerate the stale `csv_seal.rs` bindings.
5. Stand up a 1-of-1 verifier and run BTC → ETH end-to-end as the first operational slice, with the operator paying gas manually (escrow automation deferred to Phase 5).

## Transfer Modes: CLI Surface and Staged Implementation Plan

CSV follows RGB. A transfer is one of two **user-selected modes, chosen explicitly per transfer** (RFC-0012 "Transfer Modes"). This section specifies the CLI surface and a staged plan. It is design-only; no code is committed by this document.

Decisions frozen for the CLI:

- **Distinct subcommands**, not a `--mode` flag. The verb is the mode.
- **No default.** The mode subcommand is required; a bare `transfer` errors and points to the two verbs. This prevents silently minting when the user meant an off-chain transfer, and vice-versa.
- The thin-registry work in the phases above is the on-chain component of the **materialize** mode. The **interactive** mode does not touch a destination contract at all.

### CLI surface

Recipient-side (interactive mode):

```text
csv cross-chain invoice --schema <sanad-type> --seal <dest-seal-ref>
    → emits an invoice binding a single-use seal the recipient controls on the destination chain

csv cross-chain accept <consignment-file>
    → client-side validates the consignment (csv-verifier) and accepts it into the wallet; no chain tx
```

Sender-side:

```text
csv cross-chain send --from <src> --sanad-id <X> --invoice <blob>
    → interactive off-chain: assigns the sanad to the invoice's seal, closes the source seal,
      emits a consignment file for off-band delivery. No destination tx, no destination gas, no attestor.

csv cross-chain materialize --from <src> --to <dst> --sanad-id <X> --dest-owner <Y> --proof <attestor|zk>
    → materializes the sanad as an on-chain object via the thin-registry mint.
      --proof attestor : interim authenticity (RFC §9), available first
      --proof zk       : target authenticity (RFC §9.5 seam), verifies a ZkSeal proof; not available until the prover lands
```

Lifecycle verbs (`resume`, `status`, `list`, `retry`) are retained. `resume`/`retry` apply primarily to **materialize** (which has asynchronous destination finality); interactive `send` may still journal source-seal close and consignment handoff, but has no destination phase to resume.

Migration: the current `cross-chain transfer` verb is replaced by `send` + `materialize`. Keep `transfer` as a deprecation shim that errors with guidance to pick a mode, so existing scripts fail loudly rather than silently changing behavior.

### Interactive off-chain mode — design (greenfield)

Only a `validate consignment` JSON stub exists today ([validate.rs](../../csv-cli/src/commands/validate.rs)). The seal definition itself is **already implemented and chain-specific**: `SealPoint` ([csv-hash/src/seal.rs](../../csv-hash/src/seal.rs)) is the seal, with per-chain `id` (Bitcoin OutPoint / Sui ObjectID / Aptos resource addr+key / Ethereum contract+slot), a `version` field (e.g. Sui object version), and a `nonce`; the nullifier is its cross-chain replay expression. So the mode does **not** need a new seal primitive — it needs the interactive plumbing around the existing one:

- **Invoice**: recipient-issued, wraps a `SealPoint` the recipient controls on the destination chain (the RGB blinded-seal analog), the accepted sanad schema/type, and an anti-replay nonce.
- **Consignment**: the portable artifact the sender hands the recipient — the ProofBundle plus the transition history back to a validated anchor. Reuse `ProofBundle`; extend the consignment envelope beyond the current JSON stub.
- **Accept**: recipient runs full client-side validation via `csv-verifier` / `csv-algebra` (the real check, not the current structural stub) and, on success, records ownership in `csv-wallet` / `csv-store`.
- **Delivery**: file-based first; `csv-p2p` for peer delivery later.

Correctness is entirely client-side; no attestor, no ZK, no destination gas. Griefing is structurally prevented because the seal is recipient-defined.

#### Seal strength is not uniform across chains

The single-use-seal guarantee `SealPoint` expresses is only as strong as the destination chain's native model. Ordering, strongest to weakest: **Sui > Aptos > Ethereum > Solana.**

- **Sui** — owned objects with version numbers give native linear / consume-exactly-once semantics; the object *is* the seal.
- **Aptos** — Move resources are linear (cannot be copied or silently dropped), but are addressed by account + key rather than a globally unique consumed object.
- **Ethereum** — no native linearity; the seal is a contract address + storage slot whose single-use is *emulated* by a contract-maintained nullifier/used-flag mapping, so it depends on contract correctness.
- **Solana** — account/PDA model where accounts can be closed and reopened; single-use rests entirely on program logic — the weakest native guarantee, so it leans hardest on the nullifier registry.

Design implications: (1) on weaker chains the nullifier registry carries more of the single-use burden and must be enforced most carefully; (2) the same ordering informs risk when a chain is a *destination* for materialize and when it hosts the recipient seal for interactive; (3) it is a per-chain security note, not a blocker — `SealPoint` already abstracts the differences.

#### Directionality and the receiver warning

The ordering is mostly informational, with one operationally important exception: **weak-source → strong-destination transfers warrant a receiver warning.**

Rank the chains by seal strength (Bitcoin's UTXO OutPoint is the canonical strong seal, top tier with Sui; ranks are relative, not absolute scores):

| Rank | Chains | Seal basis |
|------|--------|------------|
| strongest | Bitcoin, Sui | UTXO OutPoint / owned object + version — native consume-once |
| strong | Aptos | linear Move resource (account+key addressed) |
| medium | Ethereum | emulated: contract addr + storage slot + nullifier mapping |
| weakest | Solana | account/PDA, closable+reopenable — single-use rests on program logic |

The principle: **a received sanad's security is bounded by the weakest seal in its provenance, not by the chain it now sits on.** When `strength(source) < strength(destination)`, the strong destination seal *masks* a weaker origin consumption, giving the receiver false confidence. The reverse direction (strong→weak) limits ongoing custody but does not deceive, because the receiver already knows their own chain is weak.

Defined behavior (design-only; no code committed here):

- Compute `provenance_gap = rank(destination) - rank(source)`. When the source is weaker than the destination, surface a **receiver-facing warning**.
- Warning content: name the source chain, state that its single-use seal is weaker than the receiving chain's, that the destination strength does not upgrade the origin's security, and recommend waiting for deeper source finality before treating the sanad as settled.
- Placement: at `csv cross-chain accept` (interactive — the natural receiver decision point) and at `csv cross-chain materialize` / `status` (materialize). The provenance-strength signal should also be recorded so downstream observers can see it.
- Mechanism note: the concrete risk is source-side reversal (reorg or seal reuse on the weak source) *after* the receiver accepted on the strong destination; the mitigation is stricter/deeper source-finality confirmation before accept. This dovetails with the existing strict-finality requirement — weak sources simply require a deeper confirmation bar.

### Materialize mode — design (evolves current code)

- Reuses the lock + thin-registry mint path from the phases above.
- `--proof attestor` wires to the RFC §9 verifier-signed attestation (interim).
- `--proof zk` wires to the ZK seam: the proof-carrying types already exist (`Proof::ZK`, `InclusionProof::ZkSeal`, `ZkPublicInputs`, `ZkHeader{circuit_id}`, Groth16 pairing-check error). The missing piece is a prover; the practical path is a zkVM (SP1 / RISC-Zero) proving CSV's existing Rust verifier (`csv-verifier` / `csv-algebra`) plus a source-consensus (zk-light-client) circuit. Until then `--proof zk` returns a clear not-available error.

### Staged implementation plan

Materialize track (M) — depends on the thin-registry phases above:

- **M0** — add the `materialize` verb wrapping the current lock+mint; `--proof attestor` default; `--proof zk` returns not-implemented.
- **M1** — implement RFC §9 attestor authenticity (thin-registry Phases 2–3); BTC→ETH end-to-end.
- **M2** — ZK prover: source-consensus circuit + zkVM over `csv-verifier`; wire `--proof zk`; verify `ZkSeal` on-chain; retire the attestor per chain on the §9.5 seam.

Interactive track (I) — greenfield, parallelizable with M:

- **I0** — data model: `Invoice`, `SealDefinition`, consignment envelope; pin per-chain `SealDefinition`.
- **I1** — `csv cross-chain invoice` (recipient).
- **I2** — `csv cross-chain send` (sender): assign to invoice seal, close source seal, emit consignment.
- **I3** — `csv cross-chain accept` (recipient): full client-side validation + wallet acceptance (replaces the JSON stub).
- **I4** — `csv-p2p` consignment delivery (optional; file-based works without it).

Shared (S):

- **S0** — CLI restructure: replace `transfer` with `send`/`materialize`, add `invoice`/`accept`, deprecation shim.
- **S1** — journaling/resume semantics per mode; wallet seal custody (`csv-keys`/`csv-wallet`).

Open questions to close before implementation:

- Per-chain `SealDefinition` encoding (the RGB blinded-seal analog on Sui/Aptos/EVM/BTC).
- Consignment envelope format and the completeness of client-side `accept` validation vs. the current stub.
- Whether interactive `send` needs any source-chain commitment anchoring (RGB closes a seal on-chain at send time) or stays fully off-chain in CSV's model.
