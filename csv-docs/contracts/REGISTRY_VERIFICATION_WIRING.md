# Registry Verification Wiring — thin-registry attested mint pattern

Reference pattern for the RFC-0012 §9 verifier-attested destination mint. The Ethereum
`CSVSeal` (TRM-ETH-CTR-001) is the reference implementation; Solana / Sui / Aptos contract
tickets (TRM-SOL-CTR-001 / TRM-SUI-CTR-001 / TRM-APT-CTR-001) MUST reproduce this pattern
with chain-native primitives. The byte-level digest is frozen in
[ABI_CONSTITUTION.md](ABI_CONSTITUTION.md) §9.2 — do NOT re-derive it per chain.

## The pattern in six steps

Every chain's `mint_sanad` performs these steps **in this order**:

1. **Field sanity.** Reject if `sanadId`, `commitment`, `sourceChain`, `lockEventId`, or
   `nullifier` is the zero value. A real mint always carries non-zero replay keys; a mint
   without them has no replay protection.
2. **Expiry bound.** If `attestationExpiry != 0 && now > attestationExpiry`, reject
   (`AttestationExpired`). `attestationExpiry` is a `u64` and is bound into the digest.
3. **On-chain uniqueness (anti-replay domain).** Reject if `sanadId` already minted,
   `nullifier` already used, or `lockEventId` already recorded. These three checks are the
   registry's replay protection; each is a hard reject.
4. **Recompute the frozen §9.2 digest** from the mint fields plus the chain-bound context
   (`destinationChainId`, `destinationContract`) and `keccak256(destinationOwner)`. The
   digest MUST be computed on-chain from the call arguments — never trusted from calldata.
5. **Verify `M`-of-`N` distinct verifier signatures** over the digest. Every signature must
   recover to a member of the stored verifier set; a signature from a non-member is a hard
   reject. Duplicate signatures from one verifier count once. Fewer than `threshold`
   distinct valid signers ⇒ reject.
6. **Record and emit.** Mark `sanadId`/`nullifier`/`lockEventId` consumed, persist a minimal
   mint record storing `keccak256(destinationOwner)` (not the full bytes), and emit the
   canonical `SanadMinted` event carrying the **full** `destinationOwner` bytes and the
   settlement-indexed topics.

Authority travels in the payload (the signatures), never in `msg.sender`. There is **no
caller allowlist** and mint is **not permissionless**. The gas-payer is any operator.

## Frozen digest (do not re-derive)

```text
digest = SHA256(
      "csv.mint.attestation.v1"      // 23-byte domain tag, ASCII, no NUL
   || destinationChainId             // 32 bytes = keccak256("csv.chain.<dest>")
   || destinationContract            // 32 bytes canonical contract identity on the dest chain
   || sanadId                        // 32 bytes
   || commitment                     // 32 bytes
   || sourceChain                    // 32 bytes = keccak256("csv.chain.<src>")
   || keccak256(destinationOwner)    // 32 bytes
   || lockEventId                    // 32 bytes
   || nullifier                      // 32 bytes
   || attestationExpiry              // 8 bytes, u64 big-endian; 0 = no expiry
)                                     // total preimage = 287 bytes
```

- **Hash:** SHA-256. **Signature:** secp256k1 ECDSA over that 32-byte digest (no chain
  message prefix / no domain-separator wrapping around the digest).
- `destinationChainId` = `keccak256("csv.chain.<dest>")` for the chain the contract runs on.
- `destinationContract` = the contract's own canonical 32-byte identity. **EVM:** the
  contract address left-zero-padded to 32 bytes (`bytes32(uint256(uint160(address(this))))`).
  **Solana/Sui/Aptos:** the native 32-byte program/package/module identity — pin the exact
  form in that chain's ABI freeze before implementing.
- Including `destinationChainId` + `destinationContract` is what makes a signature
  non-replayable across chains and across redeployments. Never omit them.

## Native verify primitive per chain

One secp256k1 verifier keypair serves all chains because SHA-256 + secp256k1 is the common
denominator verifiable natively everywhere:

| Chain | Primitive | Stored verifier identity |
|-------|-----------|--------------------------|
| Ethereum (EVM) | `ecrecover(digest, v, r, s)` | 20-byte address = last 20 bytes of `keccak256(pubkey)` |
| Solana | `secp256k1_recover` | compressed 33-byte public key |
| Sui | `ecdsa_k1::secp256k1_verify` | compressed 33-byte public key |
| Aptos | `secp256k1` stdlib | compressed 33-byte public key |

EVM note: enforce low-`s` and canonical `v ∈ {27,28}` to reject malleable signature
encodings. `ecrecover` returning `address(0)` (bad signature) MUST be treated as "not a
verifier" and rejected.

## Verifier set + threshold governance (OFF the mint path)

- Store an authorized verifier set and a threshold `M`. `M = 1` is permitted at first
  deployment (ETH fast-track); the signature vector means moving to `M`-of-`N` needs **no
  ABI change**.
- Where a chain already exposes a single immutable `verifier`, **generalize that primitive**
  into the set — do not introduce a second trust primitive.
- Rotation / revocation and threshold changes are owner/governance operations and MAY be
  timelocked. This governance touches ONLY the verifier set — never a per-mint precondition.
  It MUST NOT be evaluated inside `mint_sanad`. Reject a threshold that would exceed the
  resulting set size or drop to zero.

## Canonical `SanadMinted` event

Emit the full `destinationOwner` bytes (the contract stores only its hash) plus enough to
reconstruct settlement/replay evidence off-chain. Index the settlement-lookup keys:
`sanadId`, `lockEventId` (the settlement replay key, §10), and `nullifier`. Mint and
settlement are **distinct events** — `SanadMinted` is not `SettlementReleased`.

## What is explicitly NOT on the mint path

No installed/trusted root, no state root, no Merkle proof bytes, no leaf index, and no
governance-timelocked root rotation as a mint precondition (RFC-0012 §4). A chain MAY retain
chain-native hashing / future-SPV utilities, but they MUST NOT gate mint. The on-chain
`ProofLeafV1` leaf hashing in particular MUST NOT authenticate mint until the `bytes32`
(contract) vs `u8` (Rust MCE) chain-identity mismatch is reconciled (RFC-0012 §5).

## Failure modes covered by tests (reference: `AdversarialMintTest`)

- fresh-deploy happy mint with a valid attestation and no root install
- forged signer, wrong-payload signature, empty vector, malformed length, duplicate-signer
  under `M=2`, expired attestation
- duplicate `sanadId` / `nullifier` / `lockEventId`
- cross-deployment replay (same fields, different contract → digest mismatch → reject)
- gated `register_nullifier` (non-verifier cannot pre-register and grief)
