# CSV CLI Testnet MVP Ticket Index

This index converts the CLI-first stabilization directive into context-scoped tickets. The milestone is the **CSV CLI Testnet MVP**: the CLI must be the first complete, honest, adversarially safe application of the protocol.

## Release Gates

| Gate | Name | Requirement |
| --- | --- | --- |
| A | CLI Honest Mode | No fabricated protocol state, no lossy proof reconstruction, no local cache as canonical truth, fail-closed capability checks, readiness displayed per chain. |
| B | Same-chain Sanad MVP | At least two chains complete `wallet -> balance -> create -> publish -> verify state -> consume -> trace`. |
| C | Cross-chain MVP | One route completes source lock, finality, proof build/verify, destination mint, replay rejection, lifecycle trace, and interrupted-phase recovery. |
| D | Bitcoin-source MVP | Bitcoin Signet source works with SPV/finality proof and replay rejection. |
| E | Frontend Start Permission | Frontend wallet work starts only after Gate C. |
| F | Indexer/Explorer Start Permission | Indexer/explorer work starts only after canonical event/state/trace APIs are stable. |

## Tickets

| Epic | Ticket | Status | Security | Summary |
| --- | --- | --- | --- | --- |
| EPIC 0 | [CLI-TRUTH-001](CLI-TRUTH-001.md) | open | yes | Define the deterministic CLI golden-path gauntlet. |
| EPIC 1 | [CLI-STATE-001](CLI-STATE-001.md) | open | yes | Remove protocol decisions from local CLI state. |
| EPIC 1 | [CLI-ID-001](CLI-ID-001.md) | open | yes | Normalize Sanad ID parsing and display. |
| EPIC 2 | [CLI-CAP-001](CLI-CAP-001.md) | open | yes | Expose chain capability and readiness matrix. |
| EPIC 3 | [SANAD-CREATE-001](SANAD-CREATE-001.md) | open | yes | Route `csv sanad create` through a canonical typed request. |
| EPIC 3 | [BTC-SANAD-001](BTC-SANAD-001.md) | open | yes | Make Bitcoin Signet seal-backed Sanad creation work end to end. |
| EPIC 3 | [EVM-SANAD-001](EVM-SANAD-001.md) | open | yes | Make Ethereum Sepolia contract-backed Sanad creation work end to end. |
| EPIC 4 | [PROOF-ARTIFACT-001](PROOF-ARTIFACT-001.md) | open | yes | Replace lossy CLI proof summaries with canonical ProofBundle artifacts. |
| EPIC 4 | [PROOF-ADAPTER-001](PROOF-ADAPTER-001.md) | open | yes | Remove minimal/empty adapter proof construction. |
| EPIC 5 | [XFER-RUNTIME-001](XFER-RUNTIME-001.md) | open | yes | Display real runtime transfer receipts and replay IDs. |
| EPIC 5 | [XFER-GOLDEN-001](XFER-GOLDEN-001.md) | open | yes | Prove the first contract-chain cross-chain route. |
| EPIC 5 | [BTC-XFER-001](BTC-XFER-001.md) | open | yes | Implement Bitcoin-source cross-chain transfer. |
| EPIC 6 | [STATE-READER-001](STATE-READER-001.md) | open | yes | Wire adapter-backed state and trace readers into CLI. |
| EPIC 7 | [PROD-FAILCLOSED-001](PROD-FAILCLOSED-001.md) | open | yes | Remove production mock/fallback adapter paths. |
| EPIC 8 | [CI-GUARD-001](CI-GUARD-001.md) | open | yes | Enforce placeholder/security grep rules in CI. |
| EPIC 9 | [DEV-WORKFLOW-001](DEV-WORKFLOW-001.md) | open | no | Harden ticket index and context-pack workflow. |

## Operating Rule

Every implementation ticket must preserve this boundary:

```text
CLI = user interface + display cache + config
SDK = public facade
Runtime = protocol authority
Adapters = chain-specific execution/proof implementation
Verifier = canonical proof verification
Storage = durable replay/state/event persistence
```

Local CLI records may support display history and user convenience. They must never be presented as canonical protocol truth.
