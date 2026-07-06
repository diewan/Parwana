# Operator Runbook — Multi-Chain Thin-Registry Rollout (Solana / Sui / Aptos)

**Ticket:** TRM-ROLLOUT-001 · **Phase:** 6 (Multi-chain rollout) · **Security critical**

This runbook rolls the RFC-0012 thin-registry, verifier-attested mint out to the
three remaining destination chains — **Solana (devnet)**, **Sui (testnet)**, and
**Aptos (testnet)** — so all destinations expose the *same* mint semantics as the
live ETH path (TRM-ETH-DEPLOY-001). It covers deploy, config/manifest recording,
the five acceptance scenarios, and the cross-chain conformance check.

The mint model is uniform and non-negotiable:

- Mints are authorized **only** by an M-of-N verifier-signed attestation over the
  RFC-0012 §9.2 digest. There is **no proof-root path and no fallback mint** on
  any chain.
- The §9.2 digest binds `destinationChainId` and `destinationContract`, so an
  attestation for one chain/deployment cannot be replayed against another.
- Replay protection is expressed per chain but is semantically identical: a
  minted-once guard keyed by `sanadId`, a source-lock guard keyed by
  `lockEventId`, and a nullifier guard. Solana's weak native single-use leans
  hardest on the registry — it uses **never-closed tombstone PDAs** so a
  close+reopen cannot resurrect a spent entry.

> Prerequisite reading: [OPERATOR_MINT_BTC_ETH.md](OPERATOR_MINT_BTC_ETH.md) for
> the resumable transfer state machine, replay-entry states, retry/revert/
> duplicate handling, and the auditing surface. That flow is chain-agnostic; this
> runbook only adds the per-chain deploy + destination specifics.

---

## 0. The `destinationContract` per chain (read this first)

The single most important rollout fact: the value a verifier signs into the mint
digest as `destinationContract` differs in *what object it names* per chain, and
getting it wrong makes every mint fail closed (by design).

| Chain | `destinationContract` bound in the §9.2 digest | Recorded in manifest as |
|-------|-----------------------------------------------|-------------------------|
| Ethereum | CSVSeal contract address, left-zero-padded to 32 bytes | `ethereum.contracts[CSVSeal].address` |
| Solana | csv-seal **program id** (32-byte account) | `solana.program_id` |
| Sui | shared **`Registry` object id** (NOT the package id) | `sui.registry_id` |
| Aptos | `@csv_seal` **module address** (32-byte) | `aptos.module_address` |

The Sui case is the trap: `package_id` and `registry_id` are two different
values. The adapter reads `registry_id` from the manifest
(`get_sui_registry_id`); if it is empty, Sui mint fails closed with a clear
error. Record **both** after publish.

---

## 1. Deploy the destination contracts

All deploy scripts prefer the unified `csv` wallet; see each script header for
key import. None of these can be run from CI — they need funded testnet keys.

### Solana (devnet)

```bash
cd csv-contracts/solana/contracts && NO_DNA=1 anchor build
cd ../scripts && ./deploy.sh devnet
# Record the printed program id.
```

### Sui (testnet)

```bash
cd csv-contracts/sui && sui move build
./scripts/deploy.sh testnet
# Record BOTH the published package id AND the shared Registry object id
# (the deploy output lists created shared objects; the Registry is the
# csv_seal::registry::Registry object).
```

### Aptos (testnet)

```bash
cd csv-contracts/aptos/contracts && aptos move compile
cd ../scripts && ./deploy.sh testnet
# Record the module address and the deployment tx hash.
```

Each contract seeds an initial verifier set and mint threshold at deploy time
(1-of-1 for the initial rollout; rotation to M-of-N needs no ABI change). Record
the verifier secp256k1 **compressed (33-byte)** public keys and the threshold.

---

## 2. Record addresses and enable operator flows

Update **`deployments/deployment-manifest.json`** — the single source of truth —
for each chain:

- `solana.program_id`, `solana.network = "devnet"`, `solana.verifier_set`,
  `solana.mint_threshold`, `solana.verified = true`.
- `sui.package_id`, **`sui.registry_id`** (required — empty means fail-closed),
  `sui.verifier_set`, `sui.mint_threshold`, `sui.verified = true`.
- `aptos.module_address`, `aptos.deployment_tx`, `aptos.verifier_set`,
  `aptos.mint_threshold`, `aptos.verified = true`.

Mirror the addresses into `chains/{solana-devnet,sui-testnet,aptos-testnet}.toml`
for operator visibility (the adapters resolve authority from the manifest; the
toml comments document where each value goes).

Provide the verifier signing key to the runtime adapter out-of-band (never
committed): the Sui/Solana/Aptos adapters expose `with_verifier_key`, and mint
**fails closed without it**. Confirm each adapter is live:

### Seed the on-chain verifier set (required before mint)

Deploying the registry does NOT enable mint — the registry ships with an empty
verifier set and threshold 0 (fail-closed). The `AdminCap` holder must seed the
verifier set with the secp256k1 **compressed (33-byte)** public key(s) whose
private key(s) the runtime holds via `with_verifier_key`, then set the threshold.

**Sui testnet — deployed 2026-07-05** (package
`0xeca5c0931e91d07d9ac47c7dfd767e43554150cff31de57d3da14f315de2ca55`, Registry
`0x37f197aa1bf9af0898fd84a064484cbd876cf7d8078c486c7476b52b6521ac95`, AdminCap
`0x0a04ef04599aa4399fb033c1472e06c88c082b0a4dbeab68105b7f0b75e968d6`):

```bash
PKG=0xeca5c0931e91d07d9ac47c7dfd767e43554150cff31de57d3da14f315de2ca55
REG=0x37f197aa1bf9af0898fd84a064484cbd876cf7d8078c486c7476b52b6521ac95
CAP=0x0a04ef04599aa4399fb033c1472e06c88c082b0a4dbeab68105b7f0b75e968d6
# <verifier_pubkey> = 0x-prefixed 33-byte compressed secp256k1 key of the runtime verifier
sui client call --package $PKG --module csv_seal --function add_verifier \
    --args $CAP $REG <verifier_pubkey> --gas-budget 20000000
sui client call --package $PKG --module csv_seal --function set_threshold \
    --args $CAP $REG 1 --gas-budget 20000000
```

Then record the seeded key(s) and threshold in
`deployments/deployment-manifest.json` (`sui.verifier_set`, `sui.mint_threshold`).
Solana/Aptos have the equivalent admin calls on their registries.


```bash
csv chain status --chain solana
csv chain status --chain sui
csv chain status --chain aptos
```

---

## 3. Acceptance scenarios

Run every scenario end-to-end: **source lock → verified proof → destination mint
→ replay rejection.** All use the on-chain `materialize` verb (never a `--mode`
flag). Finality is enforced on the source; there is no skip-confirmation path.

| # | Scenario | Source lock | Destination mint |
|---|----------|-------------|------------------|
| 1 | BTC → Sui   | Bitcoin signet (6-conf) | Sui Registry mint |
| 2 | BTC → Aptos | Bitcoin signet (6-conf) | Aptos module mint |
| 3 | BTC → Solana| Bitcoin signet (6-conf) | Solana program mint |
| 4 | ETH → Sui   | Ethereum Sepolia escrow lock | Sui Registry mint |
| 5 | Sui → ETH   | Sui object lock | Ethereum CSVSeal mint |

For each scenario:

```bash
# 1. Materialize (locks source, journals, awaits finality)
csv cross-chain materialize --from <src> --to <dst> \
    --sanad-id <hex> --dest-owner <dst-addr> --wait
# (or resume once the source lock confirms:)
csv cross-chain resume <transfer-id> --wait

# 2. Confirm the mint + settlement evidence
csv cross-chain status <transfer-id>

# 3. Prove replay rejection: re-submitting the same transfer must NOT re-mint.
csv cross-chain materialize --from <src> --to <dst> \
    --sanad-id <hex> --dest-owner <dst-addr>
#   Expected: idempotent Ok (if Consumed) or ReplayDetected (if Pending/RolledBack).
#   Never a second on-chain mint. Confirm on-chain via the destination's
#   is-minted view keyed by sanad_id.
```

A scenario is **complete** only when: the source lock reached finality, the proof
verified off-chain, exactly one `SanadMinted` landed on the destination, and a
replay attempt was refused.

---

## 4. Cross-chain conformance check

The rollout requires that emitted state/event semantics are **equivalent across
chains**. Conformance is checked against
[CANONICAL_EVENT_SCHEMA.md](../contracts/CANONICAL_EVENT_SCHEMA.md) and
[ABI_CONSTITUTION.md](../contracts/ABI_CONSTITUTION.md). For each destination
chain, verify the `SanadMinted` event carries the canonical field set with
equivalent meaning:

| Canonical field | Meaning (identical across chains) | Verify |
|-----------------|-----------------------------------|--------|
| `sanadId`       | duplicate-mint key | one mint per sanadId; second refused |
| `commitment`    | committed sanad state | matches source lock commitment |
| `sourceChain`   | `keccak256("csv.chain.<name>")` | matches the source chain tag |
| `destinationOwner` | full recipient bytes | equals the `--dest-owner` supplied |
| `lockEventId`   | source-lock identity (duplicate-source-lock key) | derived from the confirmed source lock |
| `nullifier`     | replay-protection key | present in the chain's nullifier guard |
| `timestamp`     | block timestamp | destination block time |

Conformance passes when all five destination mints (scenarios 1–5) emit these
seven fields with matching values for the same transfer, and each chain's replay
guard (`sanadId` / `lockEventId` / `nullifier`) refuses a second attempt. Record
the observed event per chain alongside the scenario results.

> The canonical field dictionary — not each chain's native encoding — is the
> conformance contract. Ethereum emits a `bytes32`/`bytes` ABI event; Sui/Aptos
> emit Move events; Solana writes a registry account + CPI log. They are
> equivalent iff the seven canonical fields carry the same values.

---

## 5. Rollback / abort

If any scenario reveals a semantic divergence (e.g. a chain mints without the
full canonical field set, or a replay guard is bypassable), **stop the rollout
for that chain**: set its `verified` back to `false` in the manifest, and do not
enable operator mint flows for it. A partial rollout is acceptable — this ticket
is explicitly splittable per chain — but a chain that cannot match the uniform
semantics must not be advertised as a destination.

Never introduce a proof-root or fallback mint path to "make a chain work". If a
chain cannot express the thin-registry model, that is a contract fix
(TRM-\<chain\>-CTR-\*), not an operator workaround.

---

## 6. Invariants the operator must never bypass

- **No mint without a verifier-attested §9.2 signature.** The runtime holds no
  verifier key and cannot fabricate one; it emits an empty signature set that the
  contract rejects. Only the configured verifier(s) authorize a mint.
- **`destinationContract` / `destinationChainId` binding is load-bearing.** Never
  point an adapter at the wrong registry/program/module — a mismatched digest
  fails closed, and forcing it would break cross-chain replay protection.
- **Finality is never optional.** Every source lock reaches its configured depth
  before a proof is built. Do not lower depth to speed a scenario.
- **Replay guards are never manually cleared.** Do not close+reopen a Solana
  tombstone PDA, delete a Sui/Aptos replay table entry, or edit the replay DB.
  That reintroduces double-mint risk.
- **Sui `registry_id` is mandatory.** An empty `registry_id` is a fail-closed
  state, not a default — record it post-publish before advertising Sui.
