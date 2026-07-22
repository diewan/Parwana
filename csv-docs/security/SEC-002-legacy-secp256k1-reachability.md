# SEC-002 legacy secp256k1 reachability evidence

Date: 2026-07-23  
Base revision: `2343efce9b29b0ffc76bbcc00736049fc0813b4e`

## Invariant and removal

Accountability signatures must never resolve through the obsolete
`libsecp256k1 0.3.5` implementation. The only inverse dependency was the
unused `csv-sdk -> tiny-hderive -> libsecp256k1` edge enabled by the SDK's
`wallet` feature. `csv-sdk` had no source references to `tiny-hderive`; wallet
derivation already uses `bip32` and `k256`. Removing the unused dependency does
not change the public API or canonical protocol bytes.

The architecture suite now resolves workspace metadata with every feature and
fails if either `tiny-hderive` or `libsecp256k1` re-enters the graph.

## Consumer and adversarial evidence

The following exact commands report that the package does not exist in each
resolved graph, for both default and all-feature selections:

```text
cargo tree -e features -i libsecp256k1
cargo tree --all-features -e features -i libsecp256k1
```

They were run in Parwana, Piteka, and Hemion. Parwana's and Hemion's lockfiles
were refreshed; neither lockfile contains `tiny-hderive` or `libsecp256k1`.
Piteka's lockfile already contained neither package.

The active chain verifier uses the distinct maintained `secp256k1` crate.
Adversarial compact signatures with `r` or `s` equal to the curve order or
`2^256 - 1` are rejected by `csv-bitcoin`. Accountability mandate signatures
use Ed25519, not secp256k1, and their forged/malformed tests also fail closed.

Verification performed:

- `cargo check -p csv-sdk --all-features`: passed.
- `cargo test -p csv-architecture --test dep_graph_constitution --locked`:
  eight passed.
- `cargo test -p csv-bitcoin signatures::tests::rejects_out_of_range_r_and_s_scalars --locked`:
  passed.
- `cargo test -p csv-proof mandate_signature --locked`: two passed.
- Independent cryptographic review confirmed the removed inverse dependency
  and requested the architecture and overflowing-scalar regressions above.

Rollback is a manifest/lockfile revert, but it intentionally restores the
forbidden implementation and must fail the architecture guard. There is no
runtime migration or deployment ordering requirement. The remaining
`secp256k1` packages support chain functionality and are outside the legacy
path addressed by this ticket.

The reviewed consumers use local path pins. If `csv-sdk 0.1.5` has already
been published, registry consumers need a new package version and exact-pin
update because an immutable published artifact cannot acquire this removal.
