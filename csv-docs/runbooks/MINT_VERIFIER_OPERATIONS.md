# Mint Verifier — Operator Reference (keys, seeding, config, rotation, production)

**Ticket:** TRM-ROLLOUT-001 · **Security critical** · Covers Sui, Aptos, Solana
(destination mint) and notes for Ethereum.

This is the authoritative reference for the one thing that makes cross-chain mint
work: the **verifier keypair**. For a fast "just enable testnet" path see
[ENABLE_TESTNET_MINT.md](ENABLE_TESTNET_MINT.md); this document is the full
operational picture — generate, register, configure, change the threshold, rotate
the verifier, and what to do differently in production, per chain.

---

## 1. The model in one paragraph

CSV decides cross-chain correctness **off-chain** (the CSV verifier). The
destination contract does not re-check the proof; instead it mints only when the
transaction carries **≥ `threshold` valid signatures**, over the RFC-0012 §9.2
attestation digest, that recover to keys in its on-chain **verifier set**. So a
mint has exactly two halves that must agree:

- **on-chain**: the compressed secp256k1 **public** key(s) in the contract's
  verifier set, plus a threshold `M`.
- **runtime**: the matching **private** key(s), given to the runtime via the
  `CSV_MINT_VERIFIER_KEY` environment variable.

If either half is missing or they don't match, mint **fails closed** — it refuses
rather than minting something unauthenticated. There is no proof-root or
"skip-verification" fallback on any chain, by design.

One keypair works for all chains: the §9.2 digest is chain-agnostic, only the
signature is checked per chain (the digest binds `destinationChainId` +
`destinationContract`, so a signature for one chain/deployment can't be replayed
on another).

---

## 2. Generate the verifier keypair

secp256k1, compressed public key (33 bytes). Keep the secret out of the repo.

```bash
python3 - <<'PY'
import coincurve, json, os, stat
pk = coincurve.PrivateKey()
out = {"scheme":"secp256k1",
       "private_key_hex": pk.secret.hex(),
       "public_key_compressed_hex": pk.public_key.format(compressed=True).hex()}
p = os.path.expanduser("~/.csv/verifier-key-testnet.json")
open(p,"w").write(json.dumps(out, indent=2)); os.chmod(p, stat.S_IRUSR|stat.S_IWUSR)  # 0600
print("secret stored:", p)
print("PUBKEY (register this on-chain):", "0x"+out["public_key_compressed_hex"])
PY
```

- `PUBKEY` → seed into each chain's verifier set (§4).
- `private_key_hex` → the runtime's `CSV_MINT_VERIFIER_KEY` (§5).

For **M-of-N** generate N keypairs; seed all N public keys; set threshold M; give
each private key to the corresponding signer (they need not live in one process).

---

## 3. What "register it" means (two places)

| Where | What you register | Effect |
|-------|-------------------|--------|
| On-chain verifier set | the **public** key(s) + threshold | the contract will accept signatures from these keys |
| `deployments/deployment-manifest.json` | `verifier_set` (pubkeys), `mint_threshold` | source-of-truth record; audit + tooling; does NOT itself authorize anything |

The manifest is documentation/provenance — the **contract's** on-chain set is what
actually authorizes mints. Keep them in sync: after any on-chain change, update
the manifest.

---

## 4. Seed / enable minting, per chain

Deploy first (`csv-contracts/<chain>/scripts/deploy.sh`). Each script auto-seeds
if you export `CSV_MINT_VERIFIER_PUBKEY=<0x…33-byte pubkey>` before running it;
otherwise seed manually below. All governance is **owner/admin-gated**.

### Sui — immediate (AdminCap)

Authority = the `AdminCap` object minted to the publisher. Registry = the shared
`Registry` object id (`registry_id` in the manifest, **not** the package id).

```bash
PKG=<package_id>;  REG=<registry_id>;  CAP=<admin_cap>
sui client call --package $PKG --module csv_seal --function add_verifier   --args $CAP $REG <pubkey> --gas-budget 20000000
sui client call --package $PKG --module csv_seal --function set_threshold  --args $CAP $REG <M>      --gas-budget 20000000
# remove: --function remove_verifier --args $CAP $REG <pubkey>
```

### Solana — immediate (registry authority)

Authority = the account that ran `initialize_verifier_registry` (stored as
`registry.authority`). Use the committed helper
`csv-contracts/solana/scripts/seed-verifier.js` (needs `npm i @coral-xyz/anchor
@solana/web3.js` once; IDL at `target/idl/csv_seal.json`):

```bash
node ../scripts/seed-verifier.js init      <pubkey> <M>   # first time (creates the PDA)
node ../scripts/seed-verifier.js add       <pubkey>       # add a verifier
node ../scripts/seed-verifier.js remove    <pubkey>       # remove a verifier
node ../scripts/seed-verifier.js threshold <M>            # change threshold
node ../scripts/seed-verifier.js show                     # inspect current set
```

### Aptos — **timelocked** (owner, 7-day delay for changes)

First-time seeding is immediate; **subsequent changes are timelocked** (7 days).
`@csv_seal` is the module/account address; the signer must be the module owner.

```bash
# First-time seed (immediate): 1 verifier, threshold 1.
aptos move run --function-id @csv_seal::CSVSeal::init_mint_authority --args hex:<pubkey> --profile <p> --assume-yes

# Change verifier set / threshold — TWO steps, 7 days apart:
#   add=true adds <pubkey>; add=false removes it; new_threshold applies to the result.
aptos move run --function-id @csv_seal::CSVSeal::schedule_verifier_update \
    --args hex:<pubkey> bool:<add> u64:<new_threshold> --profile <p> --assume-yes
# ...wait TIMELOCK_PERIOD (604800s = 7 days)...
aptos move run --function-id @csv_seal::CSVSeal::execute_verifier_update --profile <p> --assume-yes
```

Ownership transfer is likewise timelocked: `schedule_ownership_transfer(new_owner)`
→ wait 7 days → `execute_ownership_transfer`.

### Ethereum — constructor verifier + owner ops

`CSVSeal` seeds an initial verifier at construction (`VERIFIER_ADDRESS` in
`Deploy.s.sol`) and exposes owner-gated verifier-set management (may be
timelocked by governance). The on-chain verifier identity is the 20-byte address
= last 20 bytes of `keccak256(pubkey)`.

---

## 5. Give the private key to the runtime (config)

The runtime and the `csv` CLI read the signing key from an environment variable
(a process secret, never a chain-config file, never logged):

```bash
export CSV_MINT_VERIFIER_KEY=$(python3 -c "import json;print(json.load(open('$HOME/.csv/verifier-key-testnet.json'))['private_key_hex'])")
```

The adapter factory ([`load_mint_verifier_key`](../../csv-adapter-factory/src/lib.rs))
loads it and attaches it to the destination adapter. Unset ⇒ the runtime logs
`no mint verifier key … will fail closed` and does not sign. The chain addresses
themselves come from `deployment-manifest.json` (resolved by
`get_sui_registry_id` / `get_aptos_module_address` / `get_solana_program_id`) and
are mirrored into `chains/*.toml` and `~/.csv/config.toml` by the deploy scripts.

For **M-of-N across processes**, each signer runs with its own
`CSV_MINT_VERIFIER_KEY`; the runtime aggregates the signatures up to `M` (the ABI
carries a vector of signatures on every chain).

---

## 6. Change the threshold / change the verifier — summary

| Operation | Sui | Solana | Aptos | Timelocked? |
|-----------|-----|--------|-------|-------------|
| Add verifier | `add_verifier` | `add_verifier` (helper `add`) | `schedule_verifier_update add=true` → `execute_verifier_update` | Aptos only (7d) |
| Remove verifier | `remove_verifier` | `remove_verifier` (helper `remove`) | `schedule_verifier_update add=false` → `execute` | Aptos only (7d) |
| Change threshold | `set_threshold` | `set_threshold` (helper `threshold`) | via `schedule_verifier_update`'s `new_threshold` → `execute` | Aptos only (7d) |
| Transfer admin/owner | transfer the `AdminCap` object | fixed at init — **no transfer ix** (choose a multisig/governance authority up front) | `schedule_ownership_transfer` → `execute` | Aptos only (7d) |

After ANY on-chain change: update `deployment-manifest.json`
(`verifier_set`/`mint_threshold`) and, if you added/rotated the key the runtime
uses, update `CSV_MINT_VERIFIER_KEY` accordingly.

**Rotation without downtime** (recommended): add the new verifier and raise the
set to include both old+new, deploy the new key to the runtime, confirm mints
sign with it, then remove the old verifier. Lowering `threshold` below the number
of independent signers you actually run will let fewer parties authorize mints —
change it deliberately.

---

## 7. What should be in production (do NOT ship testnet posture)

General:

- **M-of-N, not 1-of-1.** Use ≥ 2 independent verifier keys with `threshold ≥ 2`,
  held by different operators / systems. A single compromised key must not be
  able to authorize a mint.
- **Keys in an HSM/KMS**, not a 0600 file. `CSV_MINT_VERIFIER_KEY`-from-env is a
  testnet convenience; in production the signer should call out to an HSM/KMS and
  the raw secret should never sit in an env var or on disk.
- **Custody separation.** The verifier signer(s), the contract admin/owner, and
  the program upgrade authority should be distinct principals. Whoever holds the
  admin key can change the verifier set; whoever holds the upgrade authority can
  replace the code — treat both as high as the verifier key itself.
- **Prefer timelocked rotation.** Aptos enforces a 7-day timelock natively; on
  Sui/Solana, gate the admin/authority behind a multisig + your own timelock so
  verifier-set changes are reviewable, not instant.
- **Monitor** the on-chain `VerifierAdded` / `VerifierRemoved` / `ThresholdUpdated`
  events and alert on any change you did not initiate — an unexpected one is a
  compromise indicator.
- **Blast radius (RFC-0012 §9.4).** A compromised verifier set can forge an
  on-chain mint *record* and wrongly trigger escrow settlement, but cannot forge a
  `ProofBundle` a recipient's client-side validation accepts. Keep escrow limits
  bounded and settlement independently reviewable.
- Consider **making the program/package immutable** on mainnet (drop the upgrade
  authority) once stable, so only the verifier-set path — not arbitrary code — can
  change behavior.

Per-chain in production:

- **Sui**: the `AdminCap` is a bearer object — custody it in a multisig/cold
  wallet; do not leave it in a hot deploy wallet. Consider burning/locking it
  behind governance once the verifier set is settled.
- **Solana**: set the registry `authority` to a governance/multisig; hold the
  program **upgrade authority** separately (or set it to a multisig, or make the
  program non-upgradeable). `--max-len` sized to exact bytes blocks larger
  upgrades — size in headroom deliberately if you expect the program to grow.
- **Aptos**: the 7-day verifier/ownership timelock is your friend — keep it.
  Deploy under an account whose key is in an HSM/multisig; remember there is no
  un-publish, so a breaking change means a new `@csv_seal` address + manifest
  update.
- **Ethereum**: rotate off the deployer-as-verifier default; move verifier-set
  management behind timelocked governance.

---

## 8. Enable-minting checklist (any chain)

1. Generate the verifier keypair (§2). Production: N keys in HSM/KMS.
2. Deploy the contract (`deploy.sh`); record addresses in the manifest.
3. Seed the verifier public key(s) + threshold on-chain (§4). Record them in the
   manifest (`verifier_set`/`mint_threshold`).
4. Give the runtime the private key(s): `export CSV_MINT_VERIFIER_KEY=<hex>` (§5).
5. Run a transfer: `csv cross-chain materialize --from <src> --to <dst>
   --sanad-id <hex> --dest-owner <addr> --wait`. The runtime signs, the contract
   verifies against the seeded set, the mint lands, and a replay is refused.

If it won't mint, see the diagnosis table in
[ENABLE_TESTNET_MINT.md](ENABLE_TESTNET_MINT.md) §4.
