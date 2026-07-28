# Core Layer Changelog

This changelog is required for changes to protected L0-L4 public contracts:
`csv-algebra`, `csv-wire`, `csv-hash`, `csv-protocol`, and `csv-verifier`.

## Unreleased

- Established reviewed public-API snapshots and the shared conformance-corpus
  gate for in-place workspace hardening. No protocol or wire semantics changed.
- Prepared the first public Parwana V2 release. Its fixed invariant is portable
  canonical identity, destination binding, typed fail-closed assurance, atomic
  conflict handling, and reorg revocation.
- Closure support is release-specific rather than invariant-wide: Bitcoin
  signet, Ethereum sepolia, Sui testnet, Aptos testnet, and Solana devnet are
  the only advertised adapters, under the trust modes in the release manifest.
- V1 development artifacts provide no Claim C assurance and are never converted
  to V2. No earlier public Parwana release or release migration exists.
