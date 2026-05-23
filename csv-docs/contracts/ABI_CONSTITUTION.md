# Contract ABI Constitution

Frozen semantic contract for testnet. Field order and event names MUST NOT change without protocol version bump.

## Canonical Event Names

All chains MUST emit logically equivalent events. Canonical names (from `csv-core/src/events.rs`):

| Event | Required fields (semantic) |
|-------|---------------------------|
| `SanadCreated` | `sanad_id`, `commitment`, `owner` |
| `SanadConsumed` | `sanad_id`, `nullifier` |
| `CrossChainLock` | `sanad_id`, `source_chain`, `destination_chain`, `commitment` |
| `CrossChainMint` | `sanad_id`, `commitment`, `owner`, `source_chain` |
| `CrossChainRefund` | `sanad_id`, `commitment` |
| `NullifierRegistered` | `nullifier`, `sanad_id` |
| `ProofAccepted` | `proof_root`, `protocol_version` |
| `ProofRejected` | `proof_root`, `reason` |
| `ReplayDetected` | `replay_id`, `sanad_id` |

## Cross-Chain Equivalence

Implementations MUST satisfy:

- Same replay nullifier semantics on lock and mint.
- Same commitment hash algorithm (`canonical_hash` / `csv_tagged_hash` domains).
- Same protocol version constant exposed on-chain where applicable (`VERSION`).

Equivalence tests: `csv-core/tests/` constitution suite; chain-specific tests under `csv-contracts/`.

## Ethereum Reference (Sepolia)

| Contract | Role |
|----------|------|
| `CSVLock` | Source lock, nullifier registration |
| `CSVMint` | Destination mint after proof verification |

Deployed testnet addresses are recorded in `deployments/deployment-manifest.json` and `chains/ethereum.toml`.

## Immutability

- No upgradeable proxies on testnet without new manifest entry and protocol RFC.
- Bytecode hash MUST be recorded in manifest before marking `verified: true`.

## Serialization

- On-chain event topics: chain-native encoding.
- Off-chain manifest and proof bundles: canonical CBOR only (`csv-core/src/canonical.rs`).
