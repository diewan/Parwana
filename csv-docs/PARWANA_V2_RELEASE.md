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
| Portable hostile conformance manifest | `stage4-v1` | `1ff11779fb94334d24af10428996215af5b0bba30d9c754ebaee44ac11e83f0e` |
| V2 transition vectors | `1` | `0f4ef333ffbef0906ad99df2170bfab6f046aa1f1722607bd9515a17dc37e249` |
| Stage 5 closure support matrix | `1` | `29a730574e3c253757f4aae8d81364e858321b4a07d32e6e0a0f86a579a18ac2` |

Consumers pin the release declaration and verify these digests before running
the fixtures. `csv_sdk::v2::conformance_manifest()` embeds the first package.

## Compatibility and withdrawal

This is a first release, not a migration. V1 development artifacts may be
inspected only through the explicitly legacy path and always report portable
non-equivocation as unavailable. Operators must obtain a newly authorized V2
consignment; no conversion exists.

If publication validation fails, do not publish. If a defect is found after
publication, yank the affected crates, reject the unsafe version, and publish a
corrected coordinated release. Never reinterpret stored V2 bytes as V1.
