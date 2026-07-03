# Contract ABI Constitution

Frozen semantic contract for testnet. Field order, event names, and the digest layouts in this document MUST NOT change without a protocol version bump.

Authoritative source: **[RFC-0012: Thin Registry Cross-Chain Mint](../rfcs/RFC-0012-thin-registry-cross-chain-mint.md)**. Where this document and RFC-0012 disagree, RFC-0012 wins and this document is the bug. This constitution pins the byte-level parameters RFC-0012 froze at the model level (§9.2 attestation digest, §10 settlement receipt) so that every chain implements identical verification without inference.

## Cross-chain correctness model (normative)

CSV decides cross-chain validity **off-chain**. The `ProofBundle` is the canonical proof artifact; the protocol verifier runs the canonical verification flow (`validate_source_proof`) and the destination contract is a **thin registry** that records the verified result and enforces local replay protection. Destination contracts are NOT the primary cross-chain verifier (RFC-0012 §1).

### Deprecation note — proof-root gating is removed from the mint hot path

The earlier ABI model gated destination mint on an installed `trustedProofRoot` / `proofRoot` (Model B: trusted root + timelock). **That model is deprecated and MUST NOT be used to gate ordinary mint.** Under RFC-0012 §4 the following are explicitly NOT part of the canonical mint hot path:

- `trustedProofRoot`
- `proofRoot`
- `stateRoot`
- Merkle proof bytes / `leafPosition`
- governance-timelocked root rotation as a condition of mint validity

These MAY appear only in archival metadata, diagnostic tooling, or a future SPV-specific interface (RFC-0012 §9.5). They MUST NOT gate mint. Any remaining reference to `trustedProofRoot`/`proofRoot` in contract docs is historical/deprecation context only. The deployed Ethereum `CSVSeal` mint path (which gates on `proofRoot == trustedProofRoot` with `trustedProofRoot = 0`) is inoperable under this constitution and is a rewrite target, not a reference (RFC-0012 "Deployed-contract reality").

Thin registry does **not** mean permissionless mint. A registry that checks only uniqueness is trivially grief-able (front-running squats `sanadId`/`nullifier`/`lockEventId` slots). Authentication (§9 below) is a mandatory duty of the registry.

## Canonical field dictionary (normative)

These names and meanings are the single normative vocabulary for the mint ABI, events, and digests across all chains. Chains use the chain-native fixed-width form where noted; the semantic meaning is invariant.

| Field | Type | Meaning |
|-------|------|---------|
| `sanadId` | `bytes32` (or chain-native fixed 32-byte value) | Unique identifier of the sanad being materialized. Primary duplicate-mint key. |
| `commitment` | `bytes32` | Commitment hash binding the sanad's content/ownership. |
| `sourceChain` | `bytes32` = `keccak256("csv.chain.<name>")` | Fixed-width identity of the chain the sanad was locked on. Distinct from `ProofLeafV1`'s 1-byte chain id, which is unchanged (RFC-0012 §5/§6). |
| `destinationOwner` | `bytes` / chain-native byte vector | Recipient identity on the destination chain. Stored on-chain as `keccak256(destinationOwner)` for fixed width; full bytes travel in the mint event. |
| `lockEventId` | `bytes32` | Identity of the source-chain lock event. Duplicate-source-lock key; also the settlement replay key (§10). |
| `nullifier` | `bytes32` | Replay nullifier consumed by the source seal. Replay-protection key. |

`destinationChainId` = `keccak256("csv.chain.<dest>")` and `destinationContract` (canonical 32-byte contract identity on the destination chain) are digest-binding fields (§9.2) that prevent cross-chain and redeploy replay.

## Uniform mint semantics (RFC-0012 §3)

All destination chains MUST expose equivalent mint semantics:

```text
mint_sanad(sanadId, commitment, sourceChain, destinationOwner, lockEventId, nullifier)
```

with the calldata additionally carrying the verifier signatures (§9.3).

Required uniqueness checks (each is a hard reject if already present):

- `sanadId` not already minted
- `nullifier` not already used
- `lockEventId` not already recorded

Required state updates on success: mark `sanadId` minted, `nullifier` used, `lockEventId` recorded, and persist a minimal mint record (including `keccak256(destinationOwner)`) for inspection and settlement.

Required event: emit canonical `SanadMinted` (§Canonical Event Names) carrying enough data — including the full `destinationOwner` bytes — to reconstruct settlement and replay evidence off-chain.

## §9 Mint authentication (normative — TRM-SPEC-001)

Destination mint is authenticated by a **verifier-signed mint attestation**: a detached, domain-separated signature produced by an authorized verifier and carried in the mint calldata (RFC-0012 §9.1). The contract verifies the signature natively and records the mint only if authentic. Authority travels in the payload, not in whoever submits the transaction — there is **no `msg.sender` allowlist** and mint is **not permissionless**. The verifier signs only after running the canonical off-chain flow (`validate_source_proof`: source lock finalized under strict finality, seal consumed, sanad binding correct, sufficient confirmations).

### §9.2 Canonical attestation digest (frozen byte layout)

The digest is the SHA-256 of the domain tag followed by the fields below **in this exact order**. All `bytes32` fields are 32 bytes as-is (no endianness ambiguity — they are opaque hashes). `attestationExpiry` is a `u64` in **big-endian**.

```text
digest = SHA256(
      "csv.mint.attestation.v1"      // domain tag, 23 bytes, ASCII, no length prefix, no NUL terminator
   || destinationChainId             // 32 bytes  = keccak256("csv.chain.<dest>")
   || destinationContract            // 32 bytes  canonical contract identity on the destination chain
   || sanadId                        // 32 bytes
   || commitment                     // 32 bytes
   || sourceChain                    // 32 bytes  = keccak256("csv.chain.<src>")
   || keccak256(destinationOwner)    // 32 bytes  fixed-width binding; full bytes travel in the event
   || lockEventId                    // 32 bytes
   || nullifier                      // 32 bytes
   || attestationExpiry              // 8 bytes,  u64 big-endian; 0 = no expiry
)
```

Total preimage length: `23 + 8*32 + 8 = 287 bytes`.

**`destinationChainId` and `destinationContract` MUST be included.** Omitting them would let an attestation for one chain or one deployment be replayed against another. This closes the cross-chain and redeploy replay gap that the bare mint field set (§3) does not address on its own. This is the core authorization invariant — no placeholder or per-chain improvisation is acceptable.

### §9.2 Signature scheme (frozen)

- **Hash:** SHA-256 over the preimage above.
- **Signature:** secp256k1 ECDSA over that digest.
- **Native verify primitive per chain:** EVM `ecrecover`, Solana `secp256k1_recover`, Sui `ecdsa_k1`, Aptos `secp256k1` stdlib. One verifier keypair serves all chains because this hash/curve pair is the common denominator verifiable cheaply and natively on every destination VM.
- **Stored verifier identity form:**
  - EVM: 20-byte address = last 20 bytes of `keccak256(pubkey)` (recovered via `ecrecover`).
  - Non-EVM (Solana / Sui / Aptos): the compressed **33-byte** secp256k1 public key.
- The attestation hash is independent of `ProofLeafV1`'s per-chain tagged hashing, which is unchanged (RFC-0012 §5).

### §9.3 Verifier set and threshold (frozen semantics)

- The contract stores an authorized verifier set and a threshold `M`.
- Mint requires at least `M` **distinct** valid verifier signatures over the §9.2 digest. Signatures are carried as a vector (`bytes[]`) in calldata.
- `M = 1` is permitted for initial deployment (ETH fast-track). Because signatures are a vector, moving to `M`-of-`N` requires **no ABI change**.
- Where a contract already exposes an immutable `verifier` (as the Ethereum `CSVSeal` does), the thin-registry authorization SHALL **generalize that existing primitive** into the verifier set — do not introduce a second trust primitive.

### §9.3 Rotation / revocation (kept OFF the mint path)

Verifier-set rotation and revocation are owner/governance operations and MAY be timelocked. This governance touches ONLY the verifier set — **never a per-mint proof root** — so it stays off the mint hot path required by §4. Rotation/revocation MUST NOT be a precondition evaluated during `mint_sanad`.

### On-chain anti-replay domain (mint)

- On-chain uniqueness: `sanadId` + `nullifier` + `lockEventId` (§3 checks above).
- In-digest binding: `destinationChainId` + `destinationContract` + `attestationExpiry` (§9.2). Expired attestations (`attestationExpiry != 0 && now > attestationExpiry`) MUST be rejected.

### §9.4 Threat notes — forged mint attestation

- A compromised verifier set can forge an on-chain mint *record* and can wrongly trigger escrow settlement (bounded by §10). This is the stated trusted-attestor (Model C) blast radius.
- A compromised verifier set **cannot** forge a `ProofBundle` that a recipient's client-side validation accepts — that requires the real single-use seal consumed on the finalized source chain. On-chain ownership legibility degrades under compromise; the client-side ownership guarantee does not.
- `M`-of-`N` reduces single-key compromise risk. `destinationChainId` + `destinationContract` in the digest prevent a valid signature from being replayed across chains or redeployments. `attestationExpiry` bounds the validity window.

## §10 Settlement authentication (normative — TRM-SPEC-002)

The proof-delivery operator is the escrow payout beneficiary, so escrow release MUST NOT be authorized by the operator's own claim that a mint occurred (**no operator self-release, no operator-authorized release**). Release SHALL require the **same verifier set** to sign a `SettlementReceipt` digest (RFC-0012 §10). The operator submits and pays gas but cannot authorize its own payout.

### §10 Canonical settlement receipt digest (frozen byte layout)

Same construction rules as §9.2: SHA-256 over the domain tag followed by the fields in this exact order; `bytes32` as-is, `u64` big-endian.

```text
receiptDigest = SHA256(
      "csv.settlement.receipt.v1"    // domain tag, 25 bytes, ASCII, no length prefix, no NUL terminator
   || sourceChainId                  // 32 bytes = keccak256("csv.chain.<src>")
   || sourceEscrowContract           // 32 bytes canonical escrow contract identity on the source chain
   || sanadId                        // 32 bytes
   || lockEventId                    // 32 bytes  (settlement replay key)
   || destinationChainId             // 32 bytes = keccak256("csv.chain.<dest>")
   || destinationMintTxRef           // 32 bytes  canonical reference to the confirmed destination mint
   || operatorPayoutAddress          // 32 bytes  canonical payout identity on the source chain
   || receiptExpiry                  // 8 bytes,  u64 big-endian; 0 = no expiry
)
```

Total preimage length: `25 + 7*32 + 8 = 257 bytes`.

### §10 Non-EVM canonical forms (pinned)

- `sourceEscrowContract`, `operatorPayoutAddress`: EVM uses the 20-byte address **left-zero-padded to 32 bytes**. Non-EVM (Solana / Sui / Aptos) uses the native 32-byte account/address value directly.
- `destinationMintTxRef`: a 32-byte canonical reference to the confirmed destination mint. EVM: the mint transaction hash. Solana: the 32-byte transaction signature's canonical hash (`sha256(signature)` when the raw signature is 64 bytes). Sui/Aptos: the 32-byte transaction digest. It MUST identify exactly one destination mint.

### §10 Settlement anti-replay domain

The source escrow verifies **exactly one valid receipt per `lockEventId`**, releases to `operatorPayoutAddress`, and marks that `lockEventId` settled. A second receipt for the same `lockEventId` MUST be rejected. Expired receipts (`receiptExpiry != 0 && now > receiptExpiry`) MUST be rejected. On success it emits `SettlementReleased`, distinct from `SanadMinted`.

### §10 Failure handling (all four modes have defined behavior)

- **Operator paid gas but mint reverted:** no `SanadMinted`, so the verifier never observes finality and never signs a receipt; escrow is not released. The operator bears the gas loss (economic disincentive against submitting bad mints). No on-chain state changed on the destination.
- **Mint succeeded but receipt delayed:** the mint record and `lockEventId` are already recorded on the destination; the verifier signs the receipt once it observes the mint at strict finality. Escrow release is idempotent on `lockEventId`, so late delivery still settles exactly once.
- **Duplicate settlement submission:** the second submission for an already-settled `lockEventId` is rejected by the exactly-one-receipt-per-`lockEventId` rule; no double payout.
- **Source-chain reorg before final settlement:** escrow release only takes effect at source-chain strict finality; a receipt applied in a reorged block is re-evaluated against the settled-set on the canonical chain, and because `lockEventId` uniqueness is enforced on the canonical chain the payout still settles at most once.

### §10 Threat notes — forged settlement receipt

- A compromised verifier set can forge a `SettlementReceipt` and mis-direct escrow to a chosen `operatorPayoutAddress` — the settlement blast radius named in §9.4. It cannot exceed the escrowed amount for that `lockEventId`, and it cannot affect the recipient's client-side ownership.
- `sourceChainId` + `sourceEscrowContract` binding prevents a receipt from being replayed against a different chain or escrow deployment. `receiptExpiry` bounds the window. `M`-of-`N` reduces single-key risk.
- The receipt is upgradeable to a destination→source inclusion proof on the same seam as §9.5 without changing this format.

## Canonical Event Names

All chains MUST emit logically equivalent events. Mint and settlement are **distinct events** (RFC-0012 §10).

| Event | Required fields (semantic) |
|-------|---------------------------|
| `SanadCreated` | `sanadId`, `commitment`, `owner` |
| `SanadConsumed` | `sanadId`, `nullifier` |
| `CrossChainLock` | `sanadId`, `sourceChain`, `destinationChain`, `commitment`, `lockEventId` |
| `SanadMinted` | `sanadId`, `commitment`, `sourceChain`, `destinationOwner`, `lockEventId`, `nullifier` |
| `SettlementReleased` | `lockEventId`, `sanadId`, `operatorPayoutAddress`, `destinationMintTxRef` |
| `CrossChainRefund` | `sanadId`, `commitment`, `reason` |
| `NullifierRegistered` | `nullifier`, `sanadId` |
| `ReplayDetected` | `replayId`, `sanadId` |

`SanadMinted` replaces the former `CrossChainMint`. `SettlementReleased` is new and MUST NOT be conflated with mint. The former `ProofAccepted` / `ProofRejected` events belonged to the proof-root model and are **deprecated** — proof adjudication is off-chain and not signalled by an on-chain event under RFC-0012.

## Cross-Chain Equivalence

Implementations MUST satisfy:

- Same replay nullifier semantics on lock and mint.
- Same commitment hash algorithm (`canonical_hash` / `csv_tagged_hash` domains).
- Same `mint_sanad` field set and uniqueness checks (§Uniform mint semantics).
- Identical §9.2 attestation digest and §10 receipt digest byte layouts (this document is the single source; chains MUST NOT derive their own layout).
- Same protocol version constant exposed on-chain where applicable (`VERSION`).

Equivalence tests: `csv-architecture` compliance suite and chain-specific tests under `csv-contracts/`.

## Ethereum Reference (Sepolia)

| Contract | Role |
|----------|------|
| `CSVSeal` | Source lock + thin-registry destination mint (verifier-attested, §9). Its immutable `verifier` is the seed of the §9.3 verifier set. |

Deployed testnet addresses are recorded in `deployments/deployment-manifest.json` and `chains/ethereum.toml`. The current deployment's proof-root-gated mint path is inoperable under this constitution (see the deprecation note above) and is a rewrite target.

## Immutability

- No upgradeable proxies on testnet without new manifest entry and protocol RFC.
- Bytecode hash MUST be recorded in manifest before marking `verified: true`.
- The §9.2 / §10 digest layouts are frozen; changing either requires a new domain tag version (`...v2`) and a protocol version bump.

## Serialization

- On-chain event topics: chain-native encoding.
- Off-chain manifest and proof bundles: canonical CBOR only (`csv-codec`). `serde_json` is forbidden in canonical hashing paths.
- Attestation and settlement digests use SHA-256 over the fixed byte preimages defined in §9.2 / §10 — not CBOR, not `ProofLeafV1` tagged hashing.
