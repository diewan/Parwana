# Parwana V2 first release

Parwana V2 is the first public Parwana protocol release. There is no earlier
released Parwana installation or dataset to migrate. The machine-readable
release declaration is
[`conformance/parwana-v2-release.toml`](../conformance/parwana-v2-release.toml).
The completed independent security review and its evidence map are recorded in
[`security/ORG-REL-004-non-equivocation-review.md`](security/ORG-REL-004-non-equivocation-review.md).

## Exact security claim

For an exclusive source state, an isolated recipient can verify that a V2
successor consumes the source's unique closure handle and binds that
consumption to the delivered destination assignment, relative to the named
checkpoint, finality policy, proof provider, freshness bound, and trust mode.

This establishes integrity and uniquely ordered closure under the declared
closure domain. It does not establish the truth, value, legality, or
organizational authorization of referenced content. It does not make an RPC
response trustworthy, eliminate reorganizations, or turn the absence of a
conflict into proof that no conflict exists.

## Fixed protocol invariants

- V2 canonical identity, reference domains, signatures, and destination binding
  are chain-independent.
- Inspection is structural only. Claim C requires cryptographic closure
  verification against explicit recipient-owned context.
- Missing, malformed, stale, orphaned, foreign-kind, or insufficient-finality
  evidence fails closed by typed assurance dimension.
- Acceptance is atomic, conflict-aware, and reorg-revocable. Crash recovery
  never closes the same source a second time.
- A V1 artifact has no portable-closure evidence and cannot be upgraded,
  auto-detected, or presented as V2.

## Closure adapters included in this release

| Chain | Advertised network | Proof kind | Claim C trust mode |
|---|---|---|---|
| Bitcoin | signet | `bitcoin-spv-v1` | verified checkpoint/finality inputs |
| Ethereum | sepolia | `ethereum-nullifier-storage-v1` | full node or light client |
| Sui | testnet | `sui-object-consumption-v1` | full node or light client |
| Aptos | testnet | `aptos-resource-nullifier-v1` | full node or light client |
| Solana | devnet | `solana-account-nullifier-v1` | full node |

Other networks, Celestia, RPC-quorum closure, attested-registry closure, and
Solana light-client closure are not advertised by this release. Compiling an
adapter or enabling an SDK feature is not evidence that its closure claim is
supported.

## Canonical packages

| Package | Version | SHA-256 |
|---|---|---|
| Portable hostile conformance manifest | `stage5-v2` | `3991d66604d4df779fb1eba376b27428d6a8c0b043cdccf3019f13707f648eaa` |
| V2 protocol reason-code registry | `1` | `63b8fb265fd76351a9aeebd65fec7ec9c0e2aa4ea0f80d4631946408501038f5` |
| V2 transition vectors | `2` | `34c4cd2527994899e8ba152028fac1860b341a29dd100cc128ecfab6b8c0b0d1` |
| Stage 5 closure support matrix | `1` | `29a730574e3c253757f4aae8d81364e858321b4a07d32e6e0a0f86a579a18ac2` |

Consumers pin the release declaration and verify these digests before running
the fixtures. `csv_sdk::v2::conformance_manifest()` embeds the first package.

The reason-code registry is the vocabulary the conformance manifest's
`expected_reason_code` fields are drawn from, and the only vocabulary a
consumer should route V2 outcomes on. It is generated from the implementation's
own `registry_id` functions and reachable as `csv_sdk::reason_codes::contains`,
so a consumer can check a code without trusting a copied list. It is disjoint
from the V1 `ACCOUNTABILITY.*` registry.

## Compatibility and withdrawal

This is a first release, not a migration. V1 development artifacts may be
inspected only through the explicitly legacy path and always report portable
non-equivocation as unavailable. Operators must obtain a newly authorized V2
consignment; no conversion exists.

If publication validation fails, do not publish. If a defect is found after
publication, yank the affected crates, reject the unsafe version, and publish a
corrected coordinated release. Never reinterpret stored V2 bytes as V1.
