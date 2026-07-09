# Pattern: wallet-derived ownership-proof signing per chain

**Resolved in:** `CLI-PUBLISH-MULTICHAIN-001`
**Reference file:** `csv-cli/src/commands/sanads.rs` (`sign_ownership_proof`)
**Applies to:** `SANAD-OWNERSHIP-PROOF-VERIFY-001`, any new destination chain, `PQ-MLDSA-001`

## What the gap was

`csv sanad create` could only attach a real signed `OwnershipProof` for Bitcoin.
Every other chain set `proof_bytes = None` and fell closed before persisting an
Active Sanad, so Ethereum/Solana/Sui/Aptos users could only produce an unsigned
local draft via `--skip-publish`.

An earlier implementation had leaked raw wallet seed material as a forged proof.
That must never return.

## Correct implementation shape

- One signing function takes the chain, the 64-byte BIP-39 seed, the derivation
  path components, and the canonical `OwnershipProof::signing_message(...)`
  preimage. It returns `Option<OwnershipProof>` — `None` for any unsupported
  chain or any failed step.
- Key derivation always goes through `csv_keys::bip44::derive_key` (BIP-86 for
  Bitcoin, BIP-44/SLIP-10 elsewhere, dispatched inside `csv-keys`). The signing
  function never touches the seed directly.
- The signature scheme is selected **by chain**, matching each adapter's declared
  scheme. Getting this wrong produces a proof the runtime rejects.
- The freshly built proof is **self-checked before it is returned**: the
  signature must verify, and the signing key must derive back to `owner`. This
  makes it impossible for the caller to publish a proof the runtime would reject.
- The caller fails closed when the proof is `None`. It never publishes, and never
  substitutes seed bytes.

## Minimal reference excerpt

```rust
// csv-cli/src/commands/sanads.rs
let secret = csv_keys::bip44::derive_key(seed, core_chain, account, index).ok()?;
let key_bytes = secret.as_bytes();
let message = OwnershipProof::signing_message(descriptor_hash, commitment, salt, owner);

let (proof, public_key, scheme) = match chain.as_str() {
    "bitcoin" | "ethereum" => {
        let sk = SecretKey::from_slice(key_bytes).ok()?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&message).ok()?;
        let sig = secp.sign_ecdsa(&msg, &sk).serialize_compact().to_vec();
        (sig, sk.public_key(&secp).serialize().to_vec(), SignatureScheme::Secp256k1)
    }
    "sui" | "aptos" | "solana" => {
        let key_array: [u8; 32] = *key_bytes;
        let signing = SigningKey::from_bytes(&key_array);
        let sig = signing.sign(&message).to_bytes().to_vec();
        (sig, signing.verifying_key().to_bytes().to_vec(), SignatureScheme::Ed25519)
    }
    other => { log::warn!("ownership signing: unsupported chain '{other}'"); return None; }
};
// ... then self-check: proof must verify AND public_key must derive to `owner`.
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-sui | Ed25519 | 32-byte raw key; address is Blake2b(0x00 ‖ pubkey) |
| csv-aptos | Ed25519 | Aptos uses a distinct nonce path in `cmd_create` |
| csv-ethereum | Secp256k1 | ECDSA over the 32-byte message digest, compact (64B), no recovery id |
| csv-bitcoin | Secp256k1 | Only chain that also carries `seed`/`sanad_seals` in the CLI record |
| csv-solana | **Ed25519, never secp256k1** | Guarded by a dedicated regression test |
| csv-celestia | unsupported | Falls into the `other =>` arm and returns `None` |

## Tests added

- Positive: `signs_and_verifies_for_all_chains` — each of the five chains
  produces a proof that verifies through the protocol verification path.
- Negative/adversarial: `solana_uses_ed25519` — asserts
  `proof.scheme == Some(SignatureScheme::Ed25519)`, pinning the one substitution
  most likely to slip through review.
- Regression/constitution: the self-check inside `sign_ownership_proof` means a
  scheme/derivation mismatch fails at creation, not at runtime verification.

## Gotchas

The `match` on `chain.as_str()` groups `"bitcoin" | "ethereum"` and
`"sui" | "aptos" | "solana"`. When adding a chain, add it to an arm explicitly —
the `other =>` arm returns `None`, so a forgotten chain fails closed rather than
picking a default scheme. That is correct; do not add a catch-all default.

The message signed is `OwnershipProof::signing_message(descriptor_hash,
commitment, salt, owner)`. It is domain-tagged and binds the owner. Do not sign
`descriptor_hash` alone, and do not re-derive the message on the verify side from
a different field order — it is bound into `SanadId` v2.

`derive_key` returns a `csv_keys::SecretKey` wrapper. Keep it in scope only as
long as needed and never log `key_bytes`, format it, or place it in an error
message.
