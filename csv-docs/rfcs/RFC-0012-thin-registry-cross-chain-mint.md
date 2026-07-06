# RFC-0012: Thin Registry Cross-Chain Mint

## Status

Proposed

## Replaces

- Replaces the destination-mint proof-root anchoring model implied by `RFC-0006: Contract ABI`

## Motivation

CSV needs a single canonical answer to one question:

Where is cross-chain correctness decided?

There are three distinct models available:

1. Full on-chain SPV
2. Merkle leaf proof plus trusted root update with timelock
3. Off-chain CSV verification with thin on-chain registries

This RFC chooses the third model and makes it the protocol rule.

The reason this must be explicit is architectural, not tactical. The rest of the CSV protocol already treats proofs as portable artifacts verified outside the destination contract. `ProofBundle`, finality rules, replay policy, and canonical verification all point in that direction. A destination contract that attempts to re-adjudicate the proof using a separate trusted-root mechanism creates a second source of truth.

That second source of truth is undesirable even before deployment:

- it duplicates protocol logic in chain-specific contracts
- it introduces governance and timelock dependencies into ordinary mint liveness
- it creates ambiguity about whether correctness is defined by the protocol verifier or by the currently installed root
- it pushes CSV toward a bridge-root model that conflicts with its stated design goals

Pre-deployment is the correct time to make this choice because the question is constitutional: it determines whether CSV is fundamentally an off-chain validated protocol with on-chain replay anchoring, or a family of destination contracts that are themselves the primary cross-chain verifiers.

## Transfer Modes (RGB-Aligned) — chosen posture

CSV follows RGB. A transfer exposes **two user-selectable modes, chosen per transfer**:

1. **Interactive off-chain (RGB-faithful, default).** The recipient issues an invoice containing a single-use seal they control; the sender assigns the sanad to that seal and produces a consignment (ProofBundle); the recipient validates client-side and accepts. There is **no destination-chain transaction, no gas on the destination, and no attestor** — correctness is entirely client-side. This is the pure CSV/RGB path.

2. **Materialization (optional on-chain object).** The sanad is materialized as a first-class on-chain object on the destination chain (registry entry usable by destination-chain contracts). This mode uses the thin-registry mint defined in the rest of this RFC. Its authenticity evolves along a fixed seam:
   - interim: verifier-signed attestation (§9) — a trusted attestor, stated as temporary
   - target: **zero-knowledge proof** — the attestor is replaced by an untrusted prover; the destination contract verifies a succinct proof of (a) source-chain inclusion/finality and (b) CSV protocol validity, materializing trustlessly. The ZK proof-carrying types already exist (`Proof::ZK`, `InclusionProof::ZkSeal`, `ZkPublicInputs`, `ZkHeader`).

The attestor is therefore **not** a permanent correctness dependency of CSV. It exists only on the materialization mode's on-chain path, only until the ZK prover lands, and never on the interactive mode. Sections 1–10 below specify the materialization mode's on-chain registry and its authenticity seam; they do not apply to the interactive mode.

## Proposed Change

### 1. Authoritative verification model

CSV SHALL use off-chain proof verification as the authoritative cross-chain validity rule.

In this model:

- the source-chain lock produces the evidence required for transfer
- a `ProofBundle` is the canonical proof artifact carried across chains
- CSV verification is performed off-chain according to protocol rules
- the destination contract records the verified result and enforces local replay protections

Destination-chain contracts are not the primary cross-chain verifier under this RFC.

### 2. Destination contract role

Each destination contract is a thin registry with the following duties:

- Authenticate the mint (see §9) before recording it
- Prevent duplicate mint by `sanadId`
- Prevent replay by `nullifier`
- Prevent duplicate processing of the source lock event by `lockEventId`
- Emit canonical mint events
- Store the minimum data needed for auditability, settlement, and inspection

Destination contracts MUST NOT define cross-chain correctness by requiring a trusted Merkle root, proof root, or timelocked governance root as a precondition for ordinary mint execution.

Thin registry does NOT mean permissionless mint. A registry that checks only `sanadId`, `nullifier`, and `lockEventId` uniqueness is trivially grief-able: any observer can front-run a legitimate transfer and squat those slots with a bogus record, permanently blocking the real mint. Authentication (§9) is therefore a mandatory duty of the registry, not an optional hardening.

Contracts MAY retain chain-native hashing utilities or future SPV-oriented helpers, but those are explicitly outside the canonical mint path defined by this RFC.

### 3. Uniform mint semantics

All destination chains MUST expose equivalent mint semantics:

`mint_sanad(sanadId, commitment, sourceChain, destinationOwner, lockEventId, nullifier)`

Semantic field definitions:

- `sanadId: bytes32` or chain-native fixed 32-byte value
- `commitment: bytes32`
- `sourceChain: bytes32`
- `destinationOwner: bytes` or chain-native byte vector
- `lockEventId: bytes32`
- `nullifier: bytes32`

Required checks:

- `sanadId` not already minted
- `nullifier` not already used
- `lockEventId` not already recorded

Required state updates:

- mark `sanadId` minted
- mark `nullifier` used
- mark `lockEventId` recorded
- persist minimal mint record for inspection and settlement

Required event semantics:

- emit canonical `SanadMinted`
- include enough data to reconstruct settlement and replay evidence off-chain

### 4. Removed mint hot-path requirements

The following are NOT part of the canonical destination mint hot path:

- `trustedProofRoot`
- `proofRoot`
- `stateRoot`
- Merkle proof bytes
- `leafPosition`
- governance-timelocked root rotation as a condition of mint validity

These MAY appear in archival metadata, optional diagnostic tooling, or a future SPV-specific interface, but they MUST NOT gate ordinary destination mint execution under this RFC.

### 5. ProofBundle and ProofLeafV1

`ProofBundle` remains the canonical cross-chain verification artifact.

`ProofLeafV1` remains the canonical off-chain leaf format and is NOT changed by this RFC. In particular:

- the current canonical encoding still maps chain identity to the existing one-byte chain ID in `ProofLeafV1::to_canonical_bytes()`
- this RFC does not migrate `ProofLeafV1` to `bytes32` chain identifiers

The contract ABI and the proof leaf format therefore remain distinct layers:

- contract mint ABI uses `bytes32 sourceChain = keccak256("csv.chain.<name>")`
- `ProofLeafV1` continues to use its existing canonical encoding until a separate RFC changes it

Adapters MUST apply a deterministic mapping from the same chain name into both representations.

### 6. Chain identity for contract ABI

For the contract ABI defined by this RFC:

`sourceChain = keccak256("csv.chain.<name>")`

Examples:

- `keccak256("csv.chain.bitcoin")`
- `keccak256("csv.chain.ethereum")`
- `keccak256("csv.chain.solana")`
- `keccak256("csv.chain.sui")`
- `keccak256("csv.chain.aptos")`

This gives the contract layer a stable fixed-width identifier without changing the canonical encoding of `ProofLeafV1`.

### 7. Escrow and operator economics

The protocol economics are pinned as follows:

- the proof-delivery operator submits the destination mint transaction
- the operator pays destination-chain gas up front
- the sender escrows a fee on the source chain at lock time
- escrow is released to the operator after confirmed destination mint

This RFC defines the economic model, not the deployment schedule for automating it.

### 8. Settlement model

Source-chain escrow settlement MUST be based on confirmed destination mint, not on proof-root synchronization.

The source chain MUST learn about destination mint completion through a minimal operator-submitted receipt or equivalent minimal proof of destination mint occurrence. The settlement receipt format is defined in §10.

### 9. Mint authentication (authenticity)

This section is normative and resolves the authorization question that §2–§3 depend on.

#### 9.1 Chosen model

CSV SHALL authenticate destination mint with a **verifier-signed mint attestation**: a detached, domain-separated signature produced by an authorized verifier and carried in the mint calldata. The destination contract verifies the signature natively and records the mint only if it is authentic.

This is chosen over the alternative of an authorized-caller allowlist (`msg.sender` must be an authorized operator) because:

- it decouples the gas-payer (any operator) from the authority (the signature), which is the on-chain expression of CSV's proof-carrying design — authority travels in the payload, not in whoever submits the transaction
- rotating or scaling operators does not require an on-chain governance action on every chain
- the attestation is a reproducible, auditable artifact: any third party can recompute the digest from the emitted event and re-verify it against the published verifier set

The verifier signs only after executing the canonical off-chain verification flow (`validate_source_proof`: source lock finalized under strict finality, seal consumed, sanad binding correct, sufficient confirmations). The attestation is the verifier's on-chain claim that this check passed.

#### 9.2 Canonical attestation digest

```text
digest = SHA256(
      "csv.mint.attestation.v1"      // 23-byte domain tag
   || destinationChainId             // bytes32 = keccak256("csv.chain.<dest>")
   || destinationContract            // canonical 32-byte contract identity on the destination chain
   || sanadId                        // bytes32
   || commitment                     // bytes32
   || sourceChain                    // bytes32 = keccak256("csv.chain.<src>")
   || keccak256(destinationOwner)    // fixed-width binding; full bytes travel in the event
   || lockEventId                    // bytes32
   || nullifier                      // bytes32
   || attestationExpiry              // u64 big-endian; 0 = no expiry
)
```

`destinationChainId` and `destinationContract` MUST be included. Their omission would allow an attestation for one chain or one deployment to be replayed against another. This closes the cross-chain and redeploy replay gap that the bare mint field set (§3) does not address on its own.

The attestation digest uses **SHA-256** and is signed with **secp256k1**. This pair is the common denominator verifiable cheaply and natively on every destination VM (EVM `ecrecover`, Solana `secp256k1_recover`, Sui `ecdsa_k1`, Aptos stdlib), so a single verifier keypair serves all chains. Each chain stores the verifier identity in its native form (EVM: 20-byte address = last 20 bytes of `keccak256(pubkey)`; others: the compressed 33-byte public key). The attestation hash is independent of `ProofLeafV1`'s per-chain tagged hashing, which is unchanged (§5).

#### 9.3 Verifier set and threshold

- The destination contract stores an authorized verifier set and a threshold `M`.
- Mint requires at least `M` distinct valid verifier signatures over the attestation digest (`bytes[]` signatures in calldata).
- `M = 1` is permitted for initial deployment; the ABI carries signatures as a vector so `M`-of-`N` requires no ABI change.
- Verifier-set rotation and revocation are owner/governance operations and MAY be timelocked. This governance touches ONLY the verifier set — never a per-mint proof root — so it stays off the mint hot path required by §4.
- Where a contract already exposes an immutable `verifier` (as the Ethereum `CSVSeal` does), the thin-registry authorization SHALL generalize that existing primitive into the verifier set rather than introducing a new one.

#### 9.4 Trust boundary and blast radius

This is a trusted-attestor model, consistent with Model C. Its limits are stated explicitly:

- A compromised verifier set can forge an on-chain mint *record* and can wrongly trigger escrow settlement (bounded by §10).
- A compromised verifier set CANNOT forge a `ProofBundle` that a recipient's client-side validation accepts, because that requires the real single-use seal to be consumed on the finalized source chain. On-chain ownership legibility degrades under compromise; the protocol's client-side ownership guarantee does not.
- `M`-of-`N` reduces single-key compromise risk.

#### 9.5 SPV upgrade seam

Registry semantics, events, and the mint field set are fixed independently of *how* authenticity is established. A chain MAY later replace the signature check with native source-inclusion verification (Model A) without changing the mint ABI or event schema. On-chain SPV therefore remains a per-chain, non-breaking upgrade rather than a protocol migration.

### 10. Settlement authentication

The proof-delivery operator is the escrow payout beneficiary. Escrow release MUST NOT be authorized by the operator's own claim that a mint occurred, or the operator can self-deal.

Escrow release SHALL require the same verifier set to sign a `SettlementReceipt` digest:

```text
receiptDigest = SHA256(
      "csv.settlement.receipt.v1"
   || sourceChainId
   || sourceEscrowContract
   || sanadId
   || lockEventId
   || destinationChainId
   || destinationMintTxRef        // canonical reference to the confirmed destination mint
   || operatorPayoutAddress
   || receiptExpiry
)
```

The verifier signs the receipt only after observing the destination mint at strict finality. The operator submits and pays gas but cannot authorize its own payout. The source escrow verifies exactly one valid receipt per `lockEventId`, releases to `operatorPayoutAddress`, and emits a `SettlementReleased` event distinct from `SanadMinted`. This receipt is upgradeable to a destination→source inclusion proof on the same seam as §9.5.

### 11. Canonical event schema

Events are the auditable interface of the thin registry: §9.1 requires the mint attestation to be a reproducible artifact, and that reproducibility is only realizable if the emitted event carries **enough data to recompute the §9.2 digest** and re-verify it against the published verifier set. This section fixes the canonical event schema so all destination chains emit equivalent events. It is normative for the mint and settlement events introduced by this RFC; the full cross-event catalogue and per-chain encoding table live in [`csv-docs/contracts/CANONICAL_EVENT_SCHEMA.md`](../contracts/CANONICAL_EVENT_SCHEMA.md), which MUST stay consistent with this section, and field names follow the dictionary in [`ABI_CONSTITUTION.md`](../contracts/ABI_CONSTITUTION.md).

#### 11.1 Naming and deprecations

- The destination materialization event is `SanadMinted`. The former `CrossChainMint` name is **renamed** to `SanadMinted`; implementations MUST NOT emit both.
- The proof-adjudication events `ProofAccepted` / `ProofRejected` are **deprecated** and MUST NOT be emitted. Under this RFC proof adjudication is off-chain (§1); the destination contract records an already-verified result and does not signal proof verdicts on-chain.
- `SanadMinted` (destination mint) and `SettlementReleased` (source-chain escrow release, §10) are **distinct** events and MUST NOT be conflated: the mint happens on the destination chain, settlement on the source chain.

#### 11.2 `SanadMinted`

Emitted on the destination chain by the registry after the §9 verifier-attested mint is accepted. It carries the full §3 mint field set plus a block timestamp:

| Field | Type | Meaning | Duplicate/replay role |
|-------|------|---------|-----------------------|
| `sanadId` | `bytes32` | Sanad identifier | duplicate-mint key (indexed) |
| `commitment` | `bytes32` | committed sanad state | — |
| `sourceChain` | `bytes32` | `keccak256("csv.chain.<src>")` (§6) | — |
| `destinationOwner` | `bytes` | full recipient bytes | — |
| `lockEventId` | `bytes32` | source-lock identity | duplicate-source-lock key (indexed) |
| `nullifier` | `bytes32` | replay nullifier | replay-protection key |
| `timestamp` | `u64` | destination block timestamp | — |

Rules:

- **Full `destinationOwner` bytes MUST travel in the event**, even though the contract persists only `keccak256(destinationOwner)` on-chain for fixed width (§9.2). Off-chain consumers reconstruct settlement/replay evidence and recompute the digest from the event, so truncating the owner to its hash in the event is non-conforming.
- The seven fields above, taken together with the deployment's `destinationChainId`/`destinationContract` (fixed per deployment) and `attestationExpiry`, are exactly the inputs to the §9.2 digest. An auditor recomputes `digest = SHA256("csv.mint.attestation.v1" || destinationChainId || destinationContract || sanadId || commitment || sourceChain || keccak256(destinationOwner) || lockEventId || nullifier || attestationExpiry)` and re-verifies the recovered signers against the published verifier set (§9.3).
- Semantics are uniform across chains; only the native encoding differs. Reference mapping:
  - **Ethereum**: `event SanadMinted(bytes32 indexed sanadId, bytes32 commitment, bytes32 sourceChain, bytes destinationOwner, bytes32 indexed lockEventId, bytes32 nullifier, uint256 timestamp)`
  - **Sui**: a Move event `struct` with the same fields, emitted alongside the minted object.
  - **Aptos**: a Move event with the same fields, emitted on resource mint.
  - **Solana**: registry account write plus a CPI log carrying the same fields.
  - **Bitcoin**: not applicable as a destination (interactive/off-chain destination only).

#### 11.3 `SettlementReleased`

Emitted by the **source-chain** escrow when it releases the operator's payout after verifying the §10 `SettlementReceipt`. Authorized by the verifier receipt, never by the operator's own claim.

| Field | Type | Meaning |
|-------|------|---------|
| `lockEventId` | `bytes32` | settlement replay key — exactly one release per `lockEventId` (indexed) |
| `sanadId` | `bytes32` | Sanad identifier (indexed) |
| `operatorPayoutAddress` | address (chain-native) | escrow payout beneficiary |
| `destinationMintTxRef` | `bytes32` | canonical reference to the confirmed destination mint |
| `timestamp` | `u64` | source block timestamp |

Reference mapping (Ethereum): `event SettlementReleased(bytes32 indexed lockEventId, bytes32 indexed sanadId, address operatorPayoutAddress, bytes32 destinationMintTxRef, uint256 timestamp)`. Solana/Sui/Aptos emit a native escrow-release event with the same fields.

#### 11.4 Conformance

A destination chain is event-conformant iff, for the same transfer, its `SanadMinted` carries all seven §11.2 fields with values matching the source lock and the supplied recipient, and the §9.2 digest recomputed from those fields verifies against the published verifier set. The rollout conformance check (per-chain scenarios) validates exactly this equivalence — see the operator runbook `csv-docs/runbooks/OPERATOR_ROLLOUT_MULTICHAIN.md`.

> Implementation note: the Rust `CanonicalEvent`/`SealMintedEvent` types in `csv-protocol/src/events.rs` predate this RFC and still use the older `Seal*` shape (a one-byte `source_chain` and a `source_seal_ref`) rather than the seven fields above. Aligning those types to this schema is a separate, non-breaking follow-up (it changes an off-chain representation, not the mint ABI or the on-chain event); this section is the authoritative target for that work.

## Rationale

This RFC chooses off-chain CSV verification because it best preserves the protocol's intended trust boundary and operational properties.

### Model A: Full on-chain SPV

In a full on-chain SPV design, the destination contract directly verifies source-chain inclusion and finality using on-chain proofs and chain-specific verification logic.

Advantages:

- strongest on-chain self-sufficiency
- destination mint validity is adjudicated entirely by destination-chain code
- minimal reliance on off-chain verifier software at mint time

Costs:

- highest implementation complexity
- chain-specific proof systems and header verification per destination
- high gas and compute overhead
- difficult uniformity across Bitcoin, Ethereum, Solana, Sui, and Aptos
- larger attack surface in contract code
- slower iteration on verification policy and finality rules

Why CSV does not choose it now:

- CSV’s core architecture is already built around portable proof artifacts and off-chain canonical verification
- full SPV would move the protocol center of gravity into chain-specific contracts
- it would delay or complicate multi-chain uniformity for marginal benefit at the current stage

### Model B: Merkle leaf proof plus trusted root and timelock

In this model, the destination contract accepts a Merkle proof against a root that has been installed on-chain through governance or an authorized updater, often protected by a timelock.

Advantages:

- lighter than full SPV
- destination contract can reject obviously unrecognized leaves
- easier to implement than full native verification of source chains

Costs:

- introduces a root-management authority or governance path
- mint liveness depends on root publication and root rotation timing
- creates a second verification system alongside the CSV verifier
- failure modes become about root freshness, root mismatch, and governance lag rather than proof validity alone
- still requires non-trivial proof-format coupling in each contract

Why CSV rejects it:

- it makes the trusted root, not the `ProofBundle`, the practical gate for minting
- it reintroduces bridge-like governance semantics into ordinary transfer flow
- it splits correctness across two systems: off-chain verifier and on-chain root acceptance
- it weakens the clarity of CSV’s claim that the proof travels with the asset and is verified canonically

### Model C: Off-chain CSV verification plus thin registry

In this model, the protocol verifier decides whether the transfer is valid, and the destination contract records that verified result while enforcing replay protections and emitting canonical events.

Advantages:

- single source of truth for verification semantics
- uniform verification logic across chains
- lower contract complexity and lower destination-chain cost
- clearer separation between protocol correctness and chain-local state recording
- easier evolution of proof policy, finality policy, and verifier implementation without root-governance bottlenecks
- preserves a future optional path to on-chain SPV without making it mandatory now

Tradeoffs:

- correctness depends on honest execution of the canonical off-chain verification flow
- contracts are not independently sufficient to validate the entire source proof
- operator and settlement design must be explicit because mint submission is operationally externalized

Why CSV chooses it:

- it matches the protocol’s proof-carrying design
- it keeps cross-chain semantics in the protocol layer instead of scattering them into five contract families
- it minimizes on-chain complexity while preserving the on-chain invariants that matter most: uniqueness, replay protection, and auditability

## Comparison Summary

| Property | Full On-Chain SPV | Trusted Root + Timelock | Off-Chain CSV + Thin Registry |
|----------|-------------------|-------------------------|-------------------------------|
| Cross-chain verification authority | Destination contract | Destination contract plus root updater | CSV verifier |
| Contract complexity | Highest | Medium | Lowest |
| Governance dependency for ordinary mint | Low | High | Low |
| Destination gas / compute cost | Highest | Medium | Lowest |
| Uniformity across chains | Hardest | Medium | Best |
| Verification source of truth | Single on-chain verifier per chain | Split between verifier and root | Single protocol verifier |
| Replay protection on-chain | Yes | Yes | Yes |
| Alignment with CSV proof-carrying model | Weakest | Weak | Strongest |

## Impact

BREAKING CHANGE.

This RFC changes the protocol constitution in five ways:

- destination mint validity is no longer defined by proof-root installation
- replay anchoring remains on-chain, but proof adjudication is protocol-level
- contract ABI semantics become registry-oriented rather than proof-root-oriented
- mint authenticity is established by verifier-signed attestation (§9), replacing proof-root gating as the mint precondition
- escrow settlement is tied to a verifier-signed receipt over the confirmed destination mint (§10) rather than root synchronization

### Deployed-contract reality

The current Ethereum `CSVSeal` deployment does not merely differ from this RFC — its mint path is inoperable under it. `_mint_sanad_internal` gates on `proofRoot == trustedProofRoot`, while the constructor sets `trustedProofRoot = 0` and the only path to change it is a 7-day governance timelock. A fresh deployment therefore cannot mint. The Ethereum slice of the execution plan is a rewrite of the mint entrypoint (replacing proof-root gating with §9 authentication), not an incremental change. The contract's existing immutable `verifier` is the seed of the §9.3 verifier set.

## Alternatives

### Full on-chain SPV now

Rejected for the current protocol architecture. It is coherent, but it is not the architecture CSV has chosen.

### Keep the current trusted-root and timelock model

Rejected because it creates a split source of truth and drifts CSV toward a governed bridge-root model.

## Resolved by this revision

- Mint authorization: verifier-signed attestation, `M`-of-`N` verifier set (§9).
- Settlement receipt format: verifier-signed `SettlementReceipt` digest, one per `lockEventId` (§10).
- `destinationOwner` persistence: store `keccak256(destinationOwner)` on-chain for fixed width; emit the full bytes in the mint event for off-chain reconstruction (§9.2).
- Distinct settlement event: yes — `SettlementReleased`, separate from `SanadMinted` (§10).

## Unresolved Questions

- Should a follow-up RFC migrate `ProofLeafV1` chain identity from `u8` to `bytes32`, or keep the current canonical encoding permanently? (Out of scope here; ProofLeafV1 is off the mint hot path per §5.)
- Initial verifier-set threshold and rotation cadence per chain: `M = 1` is permitted for the ETH fast-track, but the target `M`-of-`N` and rotation policy are an operational decision deferred to the execution plan's Phase 1.
- Canonical form of `destinationContract` and `destinationMintTxRef` on non-EVM chains (native address vs. hashed identity) — must be pinned before each chain's ABI freeze.
