# CSV Protocol — Concepts & Developer Primer

> **Read this first.** This is the single self-contained explanation of the CSV
> vocabulary — *Sanad, Seal, Consignment, Materialization, Seeding, Verifier,
> Attestor,* and the rest. It is written for a newcomer who wants to (a)
> understand the philosophy and (b) build on top of the platform. Every concept
> is explained the same way: **what it is → why it exists → when it enters the
> lifecycle → what it looks like**.
>
> When this doc and a normative spec disagree, the spec wins. Authoritative
> sources are linked inline: [PROTOCOL_CONSTITUTION.md](PROTOCOL_CONSTITUTION.md),
> [PROTOCOL_INVARIANTS.md](PROTOCOL_INVARIANTS.md),
> [RFC-0012](rfcs/RFC-0012-thin-registry-cross-chain-mint.md),
> [OFFLINE_VERIFICATION_MODEL.md](OFFLINE_VERIFICATION_MODEL.md),
> [WHY.md](WHY.md).

---

## How to read this document

Concepts are ordered by **priority**: the things you must understand to reason
about the protocol at all come first; specialized and future-facing machinery
comes last. If you read only Tiers 0–2 you can follow any conversation about
CSV. If you are going to write code, read Tier 5 ("Building on top") too.

| Tier | Theme | Read if you want to… |
|------|-------|----------------------|
| 0 | Philosophy | Understand *why* CSV exists and how it differs from a bridge |
| 1 | Core primitives | Name the nouns: Seal, Sanad, Commitment, Nullifier, Consignment |
| 2 | Transfer lifecycle | Follow an asset from lock to mint/accept |
| 3 | Proof, finality & replay | Understand what "verify" actually checks |
| 4 | Cross-chain mint (Materialization) | Understand the on-chain path, Verifier, Attestor, Escrow |
| 5 | Building on top | Write an adapter, call the SDK, use the CLI |
| 6 | Runtime, governance & the future | Operate it, and know what isn't built yet |

Status tags used throughout: **[impl]** implemented · **[partial]** partially
implemented / Stage 1 · **[future]** designed but not yet built.

---

# Tier 0 — Philosophy: what problem CSV solves

Everything else follows from this tier. If the mental model here is wrong, the
vocabulary will feel arbitrary.

### Client-Side Validation (CSV) **[core]**

**What.** A model where *the party receiving an asset validates its correctness
locally*, instead of trusting a global consensus, a bridge operator, or a
validator set to have validated it for them.

**Why.** Every cross-chain failure to date (>$2B in documented losses) has the
same shape: a *trusted intermediary* was compromised, coerced, or wrong.
Traditional chains transfer value *through trust*. CSV transfers value *through
proof*. See [WHY.md](WHY.md).

**How the model inverts the blockchain stack:**

```
Traditional:  Global Consensus → Global Execution → Global Replication → Global Validation
CSV:          Local Ownership → Proof-Carrying State → Client Validation → Chain-Anchored Commitments
```

The chain stops being the authoritative holder of all state and becomes three
narrower things: a **timestamping layer**, a **settlement anchor**, and a
**commitment publication surface**.

### The three principles **[core]**

1. **Chain enforces single-use.** We don't build a new validator set. We reuse
   what mature chains already do perfectly: enforce that an event happens *once*
   (Bitcoin UTXOs spent once, Sui objects deleted once, Solana PDA exclusivity,
   Ethereum contract state).
2. **Client verifies proof.** The receiver checks cryptographic evidence, not a
   bridge attestation. The proof is self-contained.
3. **Sanad stays portable.** The asset representation lives off-chain in the
   client until it needs anchoring. Moving it to a new chain is a *proof
   operation*, not a custody transfer.

### Proof-carrying ownership & offline verification **[partial]**

**What.** The proof of an asset's validity travels *with the asset* (inside a
`ProofBundle`), so a recipient can verify it with **no network connection** —
scan a QR code, get valid/invalid in milliseconds.

**Why it's the headline feature.** No bridge and no ZK light client can do this:
they all require a live query to someone else's infrastructure. Offline
verifiability is what makes agent-to-agent settlement, supply-chain handover, and
point-of-sale use cases possible.

**Status.** The architecture is offline-native. *Today* (Stage 1) header
verification still leans on an RPC quorum; full offline header validation needs
an embedded per-chain light client, which is a **Stage 3** roadmap item
([PROTOCOL_INVARIANTS.md](PROTOCOL_INVARIANTS.md) RPC Trust Model).

### Not-a-bridge (positioning) **[doctrine]**

CSV deliberately rejects the word "bridge." A bridge is a trusted verifier of
someone else's consensus. CSV is a *verification model* with no bridge contract
and no central failure point. Keep this in mind when naming things — introducing
a "trusted root" or a permanent "relayer authority" is a design smell that pulls
CSV back toward the bridge model it rejects (this is the entire argument of
[RFC-0012](rfcs/RFC-0012-thin-registry-cross-chain-mint.md)).

---

# Tier 1 — Core primitives (the nouns)

These five nouns appear in almost every file and every conversation.

### Single-Use Seal **[impl]**

**What.** The foundational primitive: a *consumable ownership condition* anchored
to a real transaction on a specific chain. A seal can be closed exactly **once**.

**Why.** Single-use is the property that gives the protocol replay resistance,
deterministic lineage, and transfer finality — all without a global ledger. A
valid state transition *consumes* a prior seal and *creates* new ones:

```
Seal Consumption → State Transition → New Seal Creation
```

**When.** A seal is created when a party locks/commits on a source chain, and
consumed when ownership moves. Its `seal_id` **must** come from a real on-chain
transaction ([PROTOCOL_INVARIANTS.md](PROTOCOL_INVARIANTS.md) Invariant 1) — you
cannot fabricate a seal off-chain.

**Shape** ([constitution §5](PROTOCOL_CONSTITUTION.md)):

```rust
pub struct Seal {
    pub seal_id: Hash,
    pub source_chain: String,
    pub source_txid: Hash,
    pub source_output_index: u32,
    pub anchor: CommitAnchor,   // binds the seal to a finalized block
    pub signature: Vec<u8>,
    pub mpc_proofs: Vec<MpcProof>,
}
```

> **`SealPoint`** is the concrete, chain-specific seal actually implemented in
> code (with pinned BTC/Sui/Aptos/EVM encodings); the nullifier is its replay
> expression. When you see `Seal` in docs and `SealPoint` in code, they are the
> same concept at different altitudes.

**`CommitAnchor`** is the sub-structure that pins a seal to on-chain state
(`contract_id, block_number, block_hash, merkle_root, index_in_block`). Every
seal must carry one with a verifiable Merkle proof to a finalized block.

### Sanad **[impl]**

**What.** The protocol's native ownership instrument — think **"asset passport."**
Not just a token or receipt: a proof-carrying, selectively-disclosable,
canonicalized provenance document that *evolves through seal consumption*.

**Why.** The Sanad is what stays portable and off-chain. It is chain-agnostic by
design, so moving an asset to a new chain re-anchors the Sanad rather than
transferring custody. It can encode ownership, provenance, claims, attestations,
rights, transfer history, and content commitments.

**When.** A Sanad exists off-chain in the holder's wallet for the asset's whole
life. It only touches a chain when it is *sealed* (committed) or *materialized*
(Tier 4).

**Shape** ([constitution §13](PROTOCOL_CONSTITUTION.md)):

```rust
pub struct Sanad {
    pub id: SanadId,          // = tagged_hash("sanad-id", fields)
    pub version: u32,
    pub transfer_id: Hash,
    pub sender: Address,
    pub recipient: Address,
    pub amount: u128,
    pub source_chain: String,
    pub destination_chain: String,
    pub nullifier: Hash,
    pub metadata: Vec<u8>,
    pub signature: Vec<u8>,
}
```

> `SanadEnvelope` (merkleized payloads for selective disclosure) is a
> **[future]** evolution tracked as a Priority-1 gap
> ([constitution §13.3](PROTOCOL_CONSTITUTION.md)).

### Commitment **[impl]**

**What.** The on-chain published value that anchors a Sanad's state. Commitments
are what chains actually store — small, domain-separated, canonical.

**Why.** Publishing a commitment *before* building a proof is a hard invariant
([Invariant 2](PROTOCOL_INVARIANTS.md)): the on-chain commitment is the
timestamped root of trust the offline proof later resolves against.

**Shape.** A commitment is derived by canonical CBOR + tagged hashing over its
fields (version, protocol-id, mpc-root, contract-id, prev, payload, seal,
domain). Never hex strings in protocol messages — always raw bytes in CBOR.

### Nullifier **[impl]**

**What.** A one-way value derived from a consumed Sanad/seal that expresses
"this has been spent." Published on the destination chain and checked before any
mint.

**Why.** It's the application-level double-spend guard, complementing the seal's
single-use property. `nullifier = tagged_hash("csv-nullifier", data)`.

**When.** Generated at spend/transfer time; checked at mint time; stored forever
in the registry (never-closed tombstone on chains that support account closure).

### Consignment **[impl]**

**What.** A *signed package* handed from sender to recipient that carries a
`ProofBundle` plus the transfer's who/what/how-much. This is the unit of
peer-to-peer transfer (the term and shape come from RGB).

**Why.** The consignment is how "the proof travels with the asset" becomes
concrete: it is the thing you actually send to the counterparty (over MCP, RPC,
relay, or a QR code).

**Shape** ([constitution §10](PROTOCOL_CONSTITUTION.md)):

```rust
pub struct Consignment {
    pub version: u32,
    pub sender: Address,
    pub recipient: Address,
    pub amount: u128,
    pub source_chain: String,
    pub destination_chain: String,
    pub proof_bundle: ProofBundle,   // the actual evidence
    pub signature: Vec<u8>,
    pub lease_id: Option<Hash>,
}
```

Consignments must pass **`ConsignmentValidator`** before entering application
state ([Invariant 3](PROTOCOL_INVARIANTS.md)).

### Invoice **[impl]**

**What.** In the *interactive* transfer mode, the **recipient** issues an
invoice containing a single-use seal *they* control. The sender then assigns the
Sanad to that seal.

**Why.** This is the RGB-faithful, fully client-side path: the recipient's seal
means there is *no destination-chain transaction, no gas, and no attestor* — the
sender just produces a consignment and the recipient validates it locally.

---

# Tier 2 — The transfer lifecycle

This is the spine that connects all the nouns. Everything in Tiers 3–4 is detail
hanging off these stages.

### The transfer flow (happy path) **[impl]**

From [constitution §10.2](PROTOCOL_CONSTITUTION.md):

```
1. Lock      — sender locks assets on the source chain, receives a Seal
2. Construct — sender builds a ProofBundle from the seal + chain data
3. Sign      — sender signs a Consignment
4. Transfer  — consignment delivered to the recipient / destination
5. Verify    — recipient (or destination contract) verifies the bundle,
               checks the replay registry
6. Mint/Accept — if verification passes, the asset materializes (on-chain)
                 or is accepted (off-chain, interactive mode)
```

### The transfer state machine (`csv-algebra`) **[impl]**

The lifecycle is encoded as a **compile-time typestate machine** in `csv-algebra`
— illegal transitions don't compile. This is why the crate must stay
transport-free (it must not depend on `csv-wire`).

```
Sealed → Locked → AwaitingFinality → ProofBuilding → ProofValidated → Minting → Completed
                                                                         └──────→ RolledBack
```

Each state is a distinct Rust type; a `Transfer<Locked>` cannot call a method
that only exists on `Transfer<ProofValidated>`. This is the mechanical
enforcement of [Invariant 5](PROTOCOL_INVARIANTS.md).

### The two transfer modes **[impl]** — the most important fork

CSV follows RGB in exposing **two user-selectable modes, chosen per transfer**
([RFC-0012, "Transfer Modes"](rfcs/RFC-0012-thin-registry-cross-chain-mint.md)):

| | **Interactive (off-chain)** — default | **Materialization (on-chain)** |
|---|---|---|
| Destination tx? | **None** | Yes — a registry mint |
| Destination gas? | None | Operator pays |
| Attestor needed? | **No** | Yes (interim) → ZK prover (target) |
| Correctness decided | Entirely client-side | Off-chain verifier, recorded on-chain |
| Use it when | Two parties transacting directly | Sanad must be usable by destination-chain contracts |

**A newcomer's most common confusion is treating "mint" as mandatory. It is not.**
The default, purest CSV path never touches the destination chain. Materialization
(Tier 4) is an *optional* mode.

### Supporting lifecycle machinery **[impl]**

- **Lease / `LeaseId`** — a TTL-scoped coordination token so multiple parties /
  processes don't drive the same transfer concurrently. `acquire_lease(ttl) → LeaseId`.
- **Execution Journal** — crash-safe, phase-by-phase record so a transfer can be
  resumed deterministically after a crash. Transfer phases *must* be journaled
  ([Invariant](PROTOCOL_INVARIANTS.md): "Execution Journal Provides Crash-Safe
  Recovery").
- **Reconciliation / Recovery / Resume / Rollback** — the deterministic recovery
  family. A resumed transfer re-exercises verification paths (including SPV) that
  a fresh transfer may skip, so these are separate code paths worth knowing exist.

---

# Tier 3 — Proof, finality & replay (what "verify" actually means)

When someone says "the recipient verifies the proof," this tier is what happens.

### ProofBundle **[impl]** — the canonical proof artifact

**What.** A self-contained DAG that is the canonical cross-chain verification
artifact. It answers four questions
([OFFLINE_VERIFICATION_MODEL.md](OFFLINE_VERIFICATION_MODEL.md)):

| Part | Question | Content |
|------|----------|---------|
| Transition proofs | *What* | the state changes |
| Seal commitments | *Who* | the L1 anchor |
| Inclusion proof | *Where* | Merkle branch to an L1 block |
| Finality proof | *Weight* | chain-specific finality evidence |

**Shape** ([constitution §4.1](PROTOCOL_CONSTITUTION.md)): `version`,
`signature_scheme`, `protocol_id`, `source_chain`, `source_txid`,
`source_output_index`, `seal`, `transition_payload(+hash)`, `finality_proof`,
`inclusion_proof`, `phase`. A verifier **must reject** a bundle whose
`signature_scheme` doesn't match the source chain adapter's configured scheme
([Invariant 10](PROTOCOL_INVARIANTS.md)).

### The proof-phase ladder **[impl]**

A proof advances through **unidirectional** phases — a transfer may only mint
when the proof reaches the top:

```
Constructed → StructuralValidated → CryptographicallyValidated
            → FinalityValidated → ReplayChecked → ConsensusBound
```

### VerificationLevel **[impl]**

The *depth* a verifier actually reached, returned alongside `is_valid` (this is a
constitutional requirement — agent-facing tools **must** return it):

```
StructuralOnly → Cryptographic → FinalityConfirmed → ReplayProtected → ConsensusVerified
```

**`VerifiedComponents`** enumerates what an offline check confirmed: `inclusion`,
`finality`, `replay_checked`, `signature_scheme`, `ownership_signature`. All must
be verified before a bundle is accepted.

### Finality **[impl]** — never optional

**What.** Proof that the source transaction is irreversible. Finality is a
**typed, independently-checked dimension** — not a boolean, and never skippable
(there is a dedicated invariant: "Finality Is Never Optional"). Do not add a
"skip confirmation" path.

**FinalityEvidence** is chain-specific:

| Chain family | Evidence variant |
|---|---|
| Bitcoin (PoW) | `CumulativeWork` |
| Ethereum | `FinalizedCheckpoint` |
| Solana | `FinalizedSlot` |
| Aptos / Sui (BFT) | `ValidatorCertificate` |
| DA layers | `DaHeaderInclusion` |

**FinalityStrength** is orthogonal to inclusion: `Probabilistic { confirmations }`
for PoW chains vs `Deterministic` for BFT chains.

### The offline verification workflow **[partial]**

From [OFFLINE_VERIFICATION_MODEL.md](OFFLINE_VERIFICATION_MODEL.md):

```
1. Hash    — recompute the tagged hash of the transition
2. Seal    — confirm the transition matches the seal commitment
3. Path    — walk the Merkle path to the state_root / merkle_root in the bundle
4. Header  — check the block header against a local trusted Checkpoint
5. Replay  — query the local ReplayDatabase with the derived ReplayId
```

Step 4 relies on a **header chain / local header cache / Checkpoint** (a trusted
block hash). Verifying that cache fully offline needs a **light client** — the
**[future]** Stage-3 item.

### Replay protection **[impl]**

- **`ReplayId`** — a 32-byte identifier derived from six fields (source chain,
  txid, output index, seal id, transition id, destination chain):
  `ReplayId = tagged_hash("csv.replay-id.v1", cbor(inputs))`.
- **`ReplayRegistry` / `ReplayDatabase`** — an **append-only** store checked
  *before* any mint, with **insert-before-mint compare-and-swap**
  ([Invariant 9](PROTOCOL_INVARIANTS.md)). Operations: `insert_if_absent` (CAS),
  `confirm_consumed`, `mark_rolled_back`, `contains`. Persisted across restarts.

### Canonical commitment machinery **[impl]** — the rules you cannot break

These are *immutable* constitutional rules; violating them fails CI.

- **Canonical CBOR** (`csv-codec`, via `ciborium`) for anything hashed or signed.
  **`serde_json` is FORBIDDEN in hashing paths** — the only serde/transport
  boundary is `csv-wire`. CBOR tags 0x1C0–0x1C4 identify ProofBundle,
  SanadEnvelope, Commitment, Seal, Consignment.
- **Tagged hashing** — all hashing goes through `csv_tagged_hash(name, data)`
  (BIP-340 style, double-tagged SHA-256). Direct `sha2`/`keccak256`/`blake3`
  calls are forbidden in protocol code.
- **Domain separation** — every cryptographic context has a unique domain tag
  (`csv.<context>.v1`); the `Domain` trait + `DomainSeparatedHash<D>` make it
  type-safe ([Invariant 7](PROTOCOL_INVARIANTS.md)).
- **`ProtocolVersion`** — semver + a hash field; implementations must reject a
  `version.major` higher than they support; upgrades follow a governed process.

### MPC proofs & selective disclosure **[partial]**

- **MPC Proof** — attests that seal signatures were produced correctly by a
  threshold of participants (`participant_count ≥ threshold`).
- **Selective disclosure / stealth addresses** — privacy tooling: reveal minimal
  provenance; derive recipient-private addresses via
  `P' = tagged_hash("csv.stealth.addr.v1", R || scan_pk)`.

---

# Tier 4 — Cross-chain mint: Materialization & the Thin Registry

This tier applies **only to the Materialization mode**. The interactive mode
never uses any of it. This is the subject of
[RFC-0012](rfcs/RFC-0012-thin-registry-cross-chain-mint.md).

### The one question RFC-0012 answers

> **Where is cross-chain correctness decided?**

Three models were on the table:

| Model | Correctness decided by | CSV verdict |
|---|---|---|
| A — Full on-chain SPV | destination contract | too complex/expensive now; kept as a future seam |
| B — Trusted root + timelock | contract *and* a governed root | **rejected** — a second source of truth, bridge-like |
| C — Off-chain verify + thin registry | the **CSV verifier**; contract just records | **chosen** |

Choosing C keeps a *single source of truth* for verification and matches the
proof-carrying design. The destination contract becomes "thin."

### Materialization **[impl]**

**What.** The transfer *verb/mode* that turns a Sanad into a first-class on-chain
object (a registry entry usable by destination-chain contracts).

**Why.** Some use cases need the asset to exist *on* the destination chain (so
other contracts can compose with it), not just as an off-chain Sanad.

**When.** Chosen per-transfer, as an alternative to interactive mode. In the CLI
it is a **verb**, not a `--mode` flag.

### Thin Registry **[impl]**

**What.** The destination contract — and the **control point for all
destination-chain minting**. Its *only* duties: authenticate the mint, prevent
duplicate mint (by `sanadId`), prevent replay (by `nullifier`), prevent duplicate
source-lock processing (by `lockEventId`), emit canonical events, store minimal
audit data. It does **not** re-verify the source proof.

**How it controls minting.** The Registry stores a **registered verifier signing
key** (a compressed secp256k1 *public* key — for `M`-of-`N`, a *set* of them plus
a threshold). A `mint_sanad` call is authorized **only** if it carries
signatures that recover to keys registered in that set — i.e. the on-chain
registration is the mint gate. No registered key ⇒ nothing can mint; change the
registered set and you change who may mint. This registration lives on-chain in
the contract (mirrored for audit in `deployment-manifest.json`, which does *not*
itself authorize anything).

**Critical nuance.** "Thin" does *not* mean "permissionless." A registry that
only checks uniqueness is trivially grief-able (anyone front-runs and squats the
slots). Authentication against the **registered verifier key** is mandatory, not
optional hardening.

Uniform mint entrypoint across all chains:

```
mint_sanad(sanadId, commitment, sourceChain, destinationOwner, lockEventId, nullifier)
```

### Verifier **[impl]**

**What.** The off-chain party that runs the canonical verification flow
(`validate_source_proof`: source lock finalized under strict finality, seal
consumed, sanad binding correct, sufficient confirmations) and then *signs* to
say "this check passed." It holds the **verifier signing key**; the CLI/runtime
carries the private half (on testnet via `CSV_MINT_VERIFIER_KEY`) and produces
the signature after off-chain verification succeeds.

**Why.** It concentrates cross-chain verification logic in one place (the
protocol verifier) instead of duplicating it into five contract families.

**The control loop.** The verifier's signing key only has authority *because its
public half is registered in the destination Registry's verifier set*. The two
halves must agree: the Registry holds the registered public key, the runtime
holds the matching private key. If they don't match (or the runtime has no key),
mint **fails closed** — there is no proof-root or skip-verification fallback on
any chain. Operational detail — generate, register, rotate — lives in
[MINT_VERIFIER_OPERATIONS.md](runbooks/MINT_VERIFIER_OPERATIONS.md).

### Attestor / verifier-signed attestation **[impl, temporary]**

**What.** The **on-chain expression** of the verifier's verdict: a
domain-separated secp256k1 signature over a canonical digest, carried in the mint
calldata. The contract verifies the signature natively and records the mint only
if authentic.

**The canonical attestation digest** ([RFC-0012 §9.2](rfcs/RFC-0012-thin-registry-cross-chain-mint.md)):

```
digest = SHA256(
     "csv.mint.attestation.v1"      // domain tag
  || destinationChainId             // keccak256("csv.chain.<dest>") — anti cross-chain replay
  || destinationContract            // 32-byte contract identity     — anti redeploy replay
  || sanadId || commitment || sourceChain
  || keccak256(destinationOwner)
  || lockEventId || nullifier || attestationExpiry )
```

SHA-256 + secp256k1 is the common denominator every destination VM can verify
natively (EVM `ecrecover`, Solana `secp256k1_recover`, Sui `ecdsa_k1`, Aptos
stdlib), so **one verifier keypair serves all chains**.

**Why "temporary."** The attestor is a *trusted* party. It is **not** a permanent
correctness dependency:
- it exists **only** on the materialization mode, **never** on interactive mode;
- it exists **only until** the ZK prover lands (the "SPV upgrade seam" §9.5),
  after which an untrusted prover replaces it.

**Blast radius** ([§9.4](rfcs/RFC-0012-thin-registry-cross-chain-mint.md)): a
compromised verifier set can forge an on-chain mint *record* and wrongly trigger
escrow settlement — but it **cannot** forge a `ProofBundle` that a recipient's
client-side validation accepts, because that requires the real seal to be
consumed on the finalized source chain. *On-chain legibility degrades under
compromise; the client-side ownership guarantee does not.*

### Verifier set, threshold & Seeding **[impl]**

- **Verifier set + threshold `M`** — the **registered verifier signing key(s)**
  the Registry stores, plus the number of distinct valid signatures a mint must
  carry. The contract holds the authorized verifier public keys and requires ≥ `M`
  of them; `M = 1` is allowed for initial deployment, and the ABI carries `bytes[]`
  signatures so growing to `M`-of-`N` needs no ABI change
  ([Invariant 8](PROTOCOL_INVARIANTS.md): authorization must use
  `meets_chain_thresholds()`). This registered set **is** the destination-mint
  access control — nothing mints without a signature recovering to a key in it.
- **Seeding** — the operator bootstrap step that *registers the initial verifier
  key(s) / threshold* in a freshly deployed Registry (owner/admin-gated; per-chain
  mechanics — Sui `AdminCap`, Solana registry authority, Aptos timelocked owner,
  Ethereum constructor — are in
  [MINT_VERIFIER_OPERATIONS.md](runbooks/MINT_VERIFIER_OPERATIONS.md) §4, fast path
  [ENABLE_TESTNET_MINT.md](runbooks/ENABLE_TESTNET_MINT.md)). Rotating the
  registered key touches *only* the verifier set, never a per-mint proof root, so
  it stays off the mint hot path.

### Mint verifier key — the runtime signing key **[impl]**

**What.** The concrete, operational form of the Verifier: a **secp256k1 private
key held by the CLI/runtime** (on testnet, via the `CSV_MINT_VERIFIER_KEY`
environment variable) that signs the §9.2 attestation digest after CSV has
verified the source proof off-chain. Where "Verifier" (above) is the *role* and
"Attestation" is the *on-chain signature*, the mint verifier key is the *secret*
that produces that signature.

**Why.** A materialization mint has **two halves that must agree**:

| Half | Held by | Content |
|---|---|---|
| **on-chain** | the Thin Registry's verifier set | the compressed secp256k1 **public** key(s) + threshold `M` |
| **runtime** | the CLI/runtime process | the matching **private** key(s) — `CSV_MINT_VERIFIER_KEY` |

The Registry authenticates a mint by recovering ≥ `M` signatures to keys in its
on-chain set; the runtime is the party that produces those signatures. If the two
halves are missing or don't match, mint **fails closed** — the runtime logs
`no mint verifier key … will fail closed` and refuses rather than minting
something unauthenticated. There is no proof-root or "skip-verification"
fallback, by design.

**When.** Loaded at runtime start by the adapter factory
([`load_mint_verifier_key`](../csv-adapter-factory/src/lib.rs)) and attached to
the destination adapter; used at mint time (Tier 2, step 6) on the
materialization path only — the interactive mode never touches it.

**One keypair serves all chains.** The §9.2 digest binds `destinationChainId` +
`destinationContract`, so a single verifier keypair signs for every destination
VM (EVM `ecrecover`, Solana `secp256k1_recover`, Sui `ecdsa_k1`, Aptos stdlib)
without a signature being replayable across chains or deployments. For **M-of-N**,
each signer runs with its own `CSV_MINT_VERIFIER_KEY` and the runtime aggregates
signatures up to `M`.

**Testnet posture vs production.** `CSV_MINT_VERIFIER_KEY`-from-env is a testnet
convenience. In production the secret should live in an HSM/KMS (never an env var
or 0600 file), and the deployment should be M-of-N with distinct custodians for
the signer, the contract admin, and the upgrade authority. Full operational
detail — generate, seed, configure, change the threshold, rotate — is in the
operator runbook [MINT_VERIFIER_OPERATIONS.md](runbooks/MINT_VERIFIER_OPERATIONS.md)
(fast path: [ENABLE_TESTNET_MINT.md](runbooks/ENABLE_TESTNET_MINT.md)).

### Escrow, Operator & Settlement **[impl]**

Because mint submission is externalized, the economics are explicit:

- **Operator** (proof-delivery operator) — submits the destination mint tx and
  **pays destination gas up front**. Authority (the signature) is decoupled from
  the gas-payer (any operator) — that decoupling *is* the on-chain expression of
  proof-carrying design.
- **Escrow** — the sender escrows a fee on the *source* chain at lock time.
- **Settlement / `SettlementReceipt`** — escrow is released to the operator only
  after a **verifier-signed receipt** over the *confirmed* destination mint
  (one receipt per `lockEventId`), so the operator can't self-deal
  ([§10](rfcs/RFC-0012-thin-registry-cross-chain-mint.md)). This emits a
  `SettlementReleased` event on the source chain, **distinct** from the
  destination's `SanadMinted`.

### Canonical events **[impl]**

The registry's auditable interface. `SanadMinted` (destination) carries the seven
fields needed to *recompute the §9.2 digest* and re-verify signatures against the
published verifier set — full `destinationOwner` bytes must travel in the event
even though only `keccak256(destinationOwner)` is stored on-chain. The old
`CrossChainMint` name is renamed to `SanadMinted`; `ProofAccepted`/`ProofRejected`
are deprecated (proof adjudication is off-chain now). Canonical catalogue:
[CANONICAL_EVENT_SCHEMA.md](contracts/CANONICAL_EVENT_SCHEMA.md).

---

# Tier 5 — Building on top

Now the practical part: where the concepts live in code and how you extend them.
Read [AGENTS.md](../AGENTS.md) for the full crate-by-crate breakdown and CLI
reference; [LAYERING.md](LAYERING.md) and CLAUDE.md for the architecture rules
that CI enforces.

### The layering you must respect **[impl]**

Strict, CI-enforced (`deny.toml` + the `csv-architecture` compliance tests).
Violations fail the build.

```
csv-sdk (public facade)
 ├ csv-runtime (transfer authority: coordinator, leases, replay DB, journal)
 └ csv-adapter-factory / optional adapters (assembly boundary)

csv-runtime
   ├ csv-admission     (backpressure — rejects excess work before state mutation)
   ├ csv-coordinator   (per-chain execution cells — isolated failure domains)
   ├ csv-observability (metrics/logging/health — chain-agnostic)
   ├ csv-protocol / csv-proof / csv-verifier
   ├ csv-hash / csv-codec / csv-wire
   ├ csv-storage
   └ csv-adapter-core  (chain-agnostic interfaces)

csv-coordinator / csv-adapter-factory
 └ feature-gated concrete adapters (bitcoin, ethereum, solana, sui, aptos)
```

Non-negotiable rules a newcomer trips over first:

- **`csv-cli` holds no protocol authority state** and must not import chain
  adapters — everything goes through `csv-runtime`
  ([Invariant](PROTOCOL_INVARIANTS.md): "CLI Holds No Protocol Authority State").
- **`csv-runtime` must not import concrete chain adapters** — chain work is dispatched
  through the coordinator + adapter registry.
- **`csv-coordinator` and `csv-adapter-factory` may assemble concrete adapters**
  behind explicit chain features; adapters never depend back on runtime.
- **`csv-algebra` must not depend on `csv-wire`** — the typestate stays
  transport-free.
- **`serde_json` never appears in a hashing path.**

### The two traits every chain adapter implements **[impl]**

To add or extend a chain, implement these under `csv-adapters/<chain>`:

- **`SealProtocol`** — how this chain expresses seals, commitments, nullifiers.
- **`ChainBackend`** — how to query the chain, broadcast, and read finality.

Adapters also declare **capabilities** (`ChainCapabilities`, RFC-0010) so the
runtime can negotiate what a chain supports, and map a chain *name* into both the
`ProofLeafV1` one-byte id *and* the contract-ABI `keccak256("csv.chain.<name>")`
(RFC-0012 §5–6). New chains can be added config-first via `chains/*.toml`
(RFC-0011).

### Where each concept lives (quick map)

| Concept | Crate / file |
|---|---|
| Typestate transfer machine | `csv-algebra` |
| Seal / Sanad / Consignment / ProofBundle types | `csv-protocol`, `csv-wire` |
| Canonical CBOR / tagged hash | `csv-codec`, `csv-hash` |
| Verification | `csv-verifier`, `csv-proof` |
| Orchestration, leases, replay DB, journal | `csv-runtime` |
| Per-chain execution cells | `csv-coordinator` |
| Backpressure boundary | `csv-admission` |
| Chain adapters | `csv-adapters/{bitcoin,ethereum,solana,sui,aptos,celestia}` |
| On-chain contracts | `csv-contracts/{ethereum,solana,sui,aptos}` |
| Public API | `csv-sdk` |
| CLI | `csv-cli` (the `csv` binary) |

### The `csv` CLI **[impl]**

The CLI is grouped by concept: `seals`, `sanads`, `proofs`, `chain`, `content`,
`contracts`, `trust`, `wallet`, `runtime`, `cross_chain`, `validate`, `inspect`.
Interactive-mode transfers use invoice/send/accept verbs; materialization is its
own verb. Full command reference is in [AGENTS.md](../AGENTS.md).

### Build & test **[impl]**

```bash
cargo build --workspace --all-features
cargo test  --workspace --all-features

cargo build -p csv-cli --release                 # the `csv` binary
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings

# runtime must stay wasm-compatible ('persistent' feature is wasm-incompatible by design):
cargo build -p csv-runtime --no-default-features --target wasm32-unknown-unknown
```

Integration tests are `#[ignore]`d and need live RPC secrets; fuzz targets live
in `fuzz/`.

---

# Tier 6 — Runtime, governance & the future

### Anti-fragile runtime **[impl]**

CSV assumes a hostile environment: *chains reorg, RPC nodes lie, proofs are
malformed, operators fail, runtimes crash, relayers equivocate.* The runtime is
built to survive it:

- **Admission** — a pressure boundary that rejects excess work *before* any state
  mutation.
- **Coordinator cells / Failure domains** — per-chain isolation so one chain's
  failure can't cascade.
- **Circuit breakers** — trip on repeated failures.
- **Byzantine containment / reorg detection** — bounded, deterministic recovery.
- **Health & observability** — chain-agnostic metrics/logging.

### Governance & assurance **[impl]**

- **Protocol Constitution** — the immutable/mutable rules
  ([PROTOCOL_CONSTITUTION.md](PROTOCOL_CONSTITUTION.md)).
- **Protocol Invariants** — the "DO NOT VIOLATE" list, many mechanically
  enforced ([PROTOCOL_INVARIANTS.md](PROTOCOL_INVARIANTS.md)).
- **Formal methods** — TLA+ models, Alloy specs, compile-fail invariant tests,
  differential fuzzing.
- **Golden Proof Corpus** — signed, immutable CBOR fixtures validated in CI so
  independent implementations stay byte-compatible.

### What is not built yet **[future]**

Be honest about these when reasoning about guarantees:

| Concept | State |
|---|---|
| **ZK prover seam** (`Proof::ZK`, `ZkPublicInputs`, `ZkHeader`) | designed; replaces the trusted attestor on the materialization path |
| **Stage-3 light client** | needed for *fully* offline header verification; today Stage 1 uses RPC quorum |
| **P2P consignment delivery** (`csv-p2p`) | deferred; SDK opt-in only, not enabled in the shipped CLI until an operator runbook and stable command surface exist |
| **Explorer / Indexer** | partial |
| **On-chain SPV (Model A)** | intentionally deferred; RFC-0012 keeps a non-breaking upgrade seam for it |
| **`SanadEnvelope` merkleized payloads** | Priority-1 gap |
| Aggregate-signature / full Merkle coverage / finality hardening | README §14 "Remaining Hardening Work" |

---

## One-paragraph summary for the impatient

CSV is **client-side validation**: the receiver of an asset verifies a
self-contained **ProofBundle** locally instead of trusting a bridge. Ownership
lives in a portable **Sanad** that evolves by consuming **Single-Use Seals**
anchored on real chains; a **Nullifier** stops double-spends and a **ReplayId** in
an append-only registry stops replays. A transfer walks a compile-time
**typestate machine** (Sealed → … → Completed) and can finish two ways: the
default **interactive** mode (recipient issues an **Invoice**, sender sends a
**Consignment**, recipient accepts — *no chain, no gas, no trusted party*), or
**Materialization**, which mints the Sanad into a **Thin Registry** on the
destination chain. That mint is authorized today by a **Verifier**'s
secp256k1 **Attestation** (an interim trusted **Attestor**, seeded by an operator,
to be replaced by a ZK prover), with an **Operator** paying gas and getting repaid
from source-chain **Escrow** via a verifier-signed **Settlement** receipt.
Everything hashed is **canonical CBOR + tagged hashes** with strict **domain
separation** — and the crate layering that enforces all of this is checked by CI.
