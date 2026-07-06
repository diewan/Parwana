# Enabling Cross-Chain Mint on Testnet — the model and the steps

**Ticket:** TRM-ROLLOUT-001 · **Security critical**

This is the plain-language guide to going from "contracts deployed" to "a
cross-chain transfer actually mints on a destination testnet." It exists because
the last mile is **not** one button — and that is deliberate. Read §1 once; it
makes the rest obvious.

> For the full operational reference — keypair generation, config, changing the
> threshold, rotating the verifier (incl. Aptos's 7-day timelock), and production
> posture per chain — see **[MINT_VERIFIER_OPERATIONS.md](MINT_VERIFIER_OPERATIONS.md)**.

---

## 1. Why mint is "fail-closed" by default (the one idea to understand)

CSV validates cross-chain correctness **off-chain**, in the CSV verifier. The
destination contract does **not** re-check the source proof. So how does the
contract know a mint is legitimate and not someone typing `mint()` with made-up
data?

Answer: a **verifier signature**. Under RFC-0012 the destination contract holds a
small set of authorized **verifier public keys** and a threshold `M`. It will
mint **only** if the transaction carries at least `M` valid signatures — over the
exact §9.2 attestation digest — that recover to keys in that set. No valid
signature ⇒ no mint. This is the whole trust model in one sentence.

That design has one direct consequence for you:

> A freshly deployed contract has an **empty** verifier set. It therefore refuses
> every mint until you (a) put a verifier public key **on the contract** and
> (b) give the matching **private key to the runtime** so it can sign. Until both
> halves exist, mint "fails closed" — it safely refuses rather than minting
> something unauthenticated.

Everything below is just doing those two halves, per chain. There is intentionally
**no** "skip verification" or proof-root fallback path — adding one would defeat
the model (see [ABI_CONSTITUTION.md](../contracts/ABI_CONSTITUTION.md)).

### The two halves, named

| Half | What it is | Where it lives | Set by |
|------|-----------|----------------|--------|
| **Public key** | 33-byte compressed secp256k1 pubkey | on-chain, in the contract's verifier set | an admin tx (`add_verifier` / `initialize_verifier_registry` / `init_mint_authority`) |
| **Private key** | the matching 32-byte secret | the runtime process (never committed) | `CSV_MINT_VERIFIER_KEY` env var |

They are one keypair. The contract checks signatures against the public half; the
runtime produces those signatures with the private half. If they don't match,
mint fails closed.

---

## 2. Current deployment state (testnet)

All three destination contracts are deployed **and** their verifier set is seeded
(steps 1–3 done), recorded in
[`deployments/deployment-manifest.json`](../../deployments/deployment-manifest.json).
Each has one verifier `0x0339e90e058f0a1e6fdc584fcfde25f6a1ec665071f53c5037303ee356a2cbe077`
and `mint_threshold: 1` (testnet key; secret at `~/.csv/verifier-key-testnet.json`).
**Only step 4 (give that secret to the runtime) remains** before a mint works.

| Chain | Network | Authority id (`destinationContract`) | Admin handle |
|-------|---------|--------------------------------------|--------------|
| Sui | testnet | Registry `0x37f197aa1bf9af0898fd84a064484cbd876cf7d8078c486c7476b52b6521ac95` | AdminCap `0x0a04ef04599aa4399fb033c1472e06c88c082b0a4dbeab68105b7f0b75e968d6` |
| Aptos | testnet | module `0x26f43311ef7924787501e27e9dce4a49a48837234017c3fd55ae2aeddeec9202` | publisher account |
| Solana | devnet | program `9ekKQYpaLkTrycYmRNRDHohYZwXycHAyfLNirUDRnRVh` | upgrade authority |

(Sui package id: `0xeca5c0931e91d07d9ac47c7dfd767e43554150cff31de57d3da14f315de2ca55`
— distinct from the Registry id; the adapter binds the **Registry**.)

---

## 3. The enable checklist

Do these once per destination chain you want to use. Steps 1–2 are already done
for the chains in §2.

### Step 0 — one keypair for the verifier

Generate a single secp256k1 keypair. The **same** keypair is used for all chains
(the §9.2 digest is chain-agnostic; only the signature is checked per chain).
Keep the secret out of the repo.

```bash
python3 - <<'PY'
import coincurve, json, os, stat
pk = coincurve.PrivateKey()
out = {"scheme":"secp256k1",
       "private_key_hex": pk.secret.hex(),
       "public_key_compressed_hex": pk.public_key.format(compressed=True).hex()}
p = os.path.expanduser("~/.csv/verifier-key-testnet.json")
open(p,"w").write(json.dumps(out, indent=2)); os.chmod(p, stat.S_IRUSR|stat.S_IWUSR)
print("secret stored 0600:", p)
print("PUBKEY:", "0x"+out["public_key_compressed_hex"])
PY
```

The printed `PUBKEY` is what you seed on-chain (step 3). The `private_key_hex` is
what the runtime uses (step 4). **Whoever holds this secret can authorize mints**
— on mainnet this would be an HSM / multi-sig `M`-of-`N`; on testnet a single
0600 file is acceptable.

### Step 1 — deploy the contract  ✅ done (§2)

Via each chain's `csv-contracts/<chain>/scripts/deploy.sh`. Those scripts record
the addresses into the manifest and print the exact step-3 command.

### Step 2 — record addresses  ✅ done (§2)

The deploy scripts write `deployment-manifest.json` and `chains/*.toml`. The
adapters resolve authority from the manifest (`get_sui_registry_id`,
`get_aptos_module_address`, `get_solana_program_id`).

### Step 3 — seed the verifier public key on-chain  ✅ done (2026-07-06)

All three chains are seeded with `0x0339e90e…c077`, threshold 1 (txns in the
manifest notes). The commands below are recorded for re-seeding / rotation.

This is an admin transaction that spends gas. It puts the step-0 `PUBKEY` into the
contract's verifier set and sets the threshold to 1.

**Sui:**
```bash
PKG=0xeca5c0931e91d07d9ac47c7dfd767e43554150cff31de57d3da14f315de2ca55
REG=0x37f197aa1bf9af0898fd84a064484cbd876cf7d8078c486c7476b52b6521ac95
CAP=0x0a04ef04599aa4399fb033c1472e06c88c082b0a4dbeab68105b7f0b75e968d6
sui client call --package $PKG --module csv_seal --function add_verifier \
    --args $CAP $REG <PUBKEY> --gas-budget 20000000
sui client call --package $PKG --module csv_seal --function set_threshold \
    --args $CAP $REG 1 --gas-budget 20000000
```

**Aptos:**
```bash
aptos move run \
  --function-id 0x26f43311ef7924787501e27e9dce4a49a48837234017c3fd55ae2aeddeec9202::CSVSeal::init_mint_authority \
  --args hex:<PUBKEY> --profile default --assume-yes
```

**Solana:** call `initialize_verifier_registry(verifiers=[<PUBKEY>], threshold=1)`
on program `9ekKQYpaLkTrycYmRNRDHohYZwXycHAyfLNirUDRnRVh` (via `anchor run` or a
small client). 

After seeding, record the pubkey and threshold in the manifest
(`verifier_set`, `mint_threshold`) so the deployment state is auditable.

### Step 4 — give the private key to the runtime  ⛔ pending

The runtime (and the `csv` CLI, which drives it) reads the verifier signing key
from an environment variable. Export the step-0 secret before running any mint:

```bash
export CSV_MINT_VERIFIER_KEY=<private_key_hex>   # 32-byte hex, 0x optional
```

The adapter factory loads it ([`load_mint_verifier_key`](../../csv-adapter-factory/src/lib.rs))
and attaches it to the destination adapter. **If it is unset, mint fails closed**
(the runtime logs `no mint verifier key … will fail closed`). This is the code
half of TRM's "factory verifier-key wiring."

### Step 5 — run a transfer

Now a materialize actually mints:

```bash
csv cross-chain materialize --from bitcoin --to sui \
    --sanad-id <hex> --dest-owner <sui-addr> --wait
csv cross-chain status <transfer-id>
```

The runtime signs the §9.2 digest with `CSV_MINT_VERIFIER_KEY`; the Sui Registry
recovers the signer, finds it in the seeded set, and mints. Replaying the same
transfer is refused (see [OPERATOR_ROLLOUT_MULTICHAIN.md](OPERATOR_ROLLOUT_MULTICHAIN.md)).

---

## 4. Quick diagnosis: "why won't it mint?"

| Symptom | Cause | Fix |
|---------|-------|-----|
| Runtime log: `no mint verifier key … fail closed` | Step 4 missing | `export CSV_MINT_VERIFIER_KEY=…` |
| Contract reverts `InsufficientSignatures` / threshold error | Step 3 missing, or pubkey ≠ the runtime's key | Seed the **matching** pubkey; set threshold ≥ 1 |
| Sui: `No mint Registry object id configured` | `registry_id` unset in manifest | Record `deployments.sui.registry_id` |
| Reverts with a digest/binding error | Adapter pointed at the wrong registry/program/module | Fix the id in the manifest — the digest binds `destinationContract` |
| Mint "succeeds" but a second one goes through | **Should be impossible** — report it | Replay guard (`sanadId`/`lockEventId`/`nullifier`) is the invariant |

---

## 5. Security notes (do not skip)

- The verifier key is the **mint trust anchor**. On testnet a single 0600 file is
  fine; for anything real use `M`-of-`N` distinct keys (`add_verifier` each, then
  `set_threshold M`) and store secrets in an HSM/KMS. The ABI already carries a
  vector of signatures, so raising `M` needs no redeploy.
- Never commit `CSV_MINT_VERIFIER_KEY` or the key file. Never log it (the loader
  never does).
- Seeding a pubkey you do not control, or a key the runtime does not hold, just
  keeps mint fail-closed — it cannot *weaken* safety, only fail to enable.
- Rotating the verifier set is an admin op (`add_verifier`/`remove_verifier` +
  `set_threshold`) and touches **only** the verifier set — never a proof root,
  never the mint hot path.
