# Parwana Testnet Deployments

Governed deployment manifest for testnet contract and program anchors.

## Files

| File | Purpose |
|------|---------|
| `deployment-manifest.json` | Canonical addresses, bytecode hashes, deployment provenance |
| `deployment-manifest.sig.json` | Detached Ed25519 signature over the manifest (RPC-006) |
| `../chains/*.toml` | Per-chain RPC, capabilities, and contract addresses |

## Signed manifest (RPC-006)

The manifest is signed with a detached Ed25519 signature. Verification covers
the **canonical CBOR** of the parsed manifest (via `csv_codec::to_canonical_cbor`),
not the JSON text — reformatting the JSON does not break the signature, but
changing any value does. A checksum alone cannot detect substitution; the
signature is the root of trust for EXP-003 startup validation, EXP-008
certification, and the wallet's drawer-verifiable registry.

- Verification keys are pinned in
  `csv-protocol/src/manifest_signature.rs::TRUSTED_MANIFEST_SIGNERS`.
- Load-time verification fails closed on a missing, malformed, wrong-signer, or
  invalid signature (`csv_protocol::manifest_signature::load_verified_manifest_from_dir`).
- The public key is trusted from the pinned set, **never** from the sidecar, so
  swapping the sidecar cannot swap the trust anchor.
- A development bypass (`allow_unsigned = true`) is compiled out of release
  builds (`debug_assertions`) and can never weaken a shipped binary.

### Signing / rotation procedure

The signing **private** key is an offline operator credential. It must never
appear in the repository, CI, or containers (EXP-001 discipline).

1. Generate a signing key offline and store it in a secret manager / HSM. Derive
   its 32-byte Ed25519 seed as hex.
2. Re-sign after any manifest change:

   ```bash
   CSV_MANIFEST_SIGNING_KEY=<64-hex-char seed> \
     cargo run -p csv-protocol --example sign_deployment_manifest -- \
       --signer-id <operator-id>
   ```

   The tool prints the public key (stdout) and writes
   `deployment-manifest.sig.json`. It never emits the private seed.
3. To rotate or add a signer, add the printed public key to
   `TRUSTED_MANIFEST_SIGNERS` (reviewable code change), re-sign, and remove the
   retired key once all consumers have shipped the new pin.
4. `cargo test -p csv-protocol --test manifest_signature_shipped` must pass from
   a fresh checkout.

> The currently pinned `csv-testnet-operator-2026-07` anchor was bootstrapped
> with an ephemeral key for testnet. Before mainnet, replace it with an
> operator-held offline key using the procedure above.

## Field semantics

- `deployments.ethereum.deployment_block` — the block that mined the **active**
  CSVSeal deployment tx. Reconciled 2026-07-15 (RPC-006) to equal
  `contracts[CSVSeal].block_number` (11225104, confirmed by the 2026-07-14
  audit). The prior value 11084747 referred to a superseded deploy attempt.
- `contracts[*].block_number` — the per-contract authority for inclusion block.

## Updating After Deploy

**Ethereum (Sepolia):**

```bash
cd csv-contracts/ethereum
./scripts/deploy.sh
```

**Manifest only (existing addresses):**

```bash
cd csv-contracts/ethereum/scripts
cargo run --bin update_manifest -- <seal_address> <tx> <block>
```

Set `VERIFIER_ADDRESS` when updating CSVSeal constructor args.

## Verification Checklist

- [ ] `bytecode_hash` populated from `deployments/artifacts/*.bin`
- [ ] `verified: true` after Etherscan / block explorer confirmation
- [ ] `chains/ethereum.toml` `contract_address` matches manifest
- [ ] `cargo test --workspace --all-features` passes
