# Portable conformance package

`manifest.json` is the versioned hostile-conformance package consumed through
`csv_sdk::v2::conformance_manifest()`. It is generated, never hand-edited:

```text
cargo run -p csv-sdk --example generate_portable_conformance
cargo run -p csv-sdk --example generate_portable_conformance -- --check
```

The generator imports `csv_sdk` and nothing else, so every byte it distributes
is reachable by any downstream consumer holding the published SDK.

## What this package is

An inventory of hostile-conformance cases, each pinning its wire and contract
versions, its expected assurance dimensions, its stable reason code, and the
Parwana test that establishes the behaviour — plus, for the cases where it is
possible, real canonical material a consumer can execute.

Each case declares its material kind:

| Kind | Meaning |
|---|---|
| `consignment-v2` | Real canonical bytes. `csv_sdk::v2::inspect` decodes them. |
| `transition-vector-ref` | The executable material is the named vector in the separately versioned transition-vector package; it is referenced, never duplicated. |
| `none` | Nothing is distributed, and the case records why. |

## What this package is not

It is not a way to reach an aggregate verdict. Every aggregate outcome depends
on a closure proof provider, a finalized checkpoint, and recipient-owned
verification context that this package does not and cannot supply. Structural
decoding is never cryptographic verification, and `expected_dimensions` is the
outcome Parwana's named test observes under its own inputs — a declared
expectation, not something this package produces.

A consumer that needs material this package does not distribute must request it
through a Parwana ticket rather than constructing its own "valid" artifact.
