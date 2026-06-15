# Tickets Index

This index converts the current grep-visible stubs/placeholders from the uploaded project into small AI-agent work units.

The repomix snapshot showed that some older `REMAINING_TASKS.md` items are already fixed or moved. Treat this index as the working backlog, but regenerate context packs before each session because the script re-finds live source snippets.

Legend:

- `ready`: full ticket file exists in this folder.
- `index-only`: row is scoped enough to become a ticket, but no detailed ticket file is included yet.
- `split`: row should be split further before an agent works it.
- `verify-first`: may already be fixed or may be test/example-only; inspect before assigning.

## Recommended first batch

| Order | Ticket | Status | Why first |
|---:|---|---|---|
| 1 | `F-CODEC-001` | ready | Small, low blast-radius workflow warm-up. |
| 2 | `E-WALLET-SIGNER-001` | ready | Removes obvious key/signing placeholders. |
| 3 | `C-CLI-UTXO-001` | ready | Removes user-facing validation bypass while checking architecture boundaries. |
| 4 | `A-ETH-REGISTRY-001` | ready | Security-critical registry verification; good reference pattern. |
| 5 | `A-SUI-MINT-001` | ready | High-impact mint placeholder removal. |
| 6 | `A-APTOS-MINT-001` | ready | Similar mint proof parsing pattern after Sui/Ethereum notes. |
| 7 | `D-SIG-MLDSA-001` | ready | Signature-critical; do with stronger model and adversarial review. |
| 8 | `B-SDK-CAPABILITY-001` | ready | Cleans public API capability/fail-closed story. |

## Ready tickets included

| Ticket | Priority | Model | Crate | Main file(s) | Stub marker(s) |
|---|---|---|---|---|---|
| `F-CODEC-001` | P2 | sonnet | `csv-codec` | `src/encode.rs`, `src/canonical.rs` | NFC TODO; simplified hash note |
| `A-SUI-MINT-001` | P1 | opus | `csv-adapters/csv-sui` | `src/ops.rs` | zero `SanadId`; zero commitment; placeholder state |
| `A-ETH-REGISTRY-001` | P1 | opus | `csv-adapters/csv-ethereum` | `src/seal_protocol.rs`, `src/runtime_adapter.rs` | skip on-chain registry verification; minimal proof bundle |
| `A-APTOS-MINT-001` | P1 | opus | `csv-adapters/csv-aptos` | `src/ops.rs` | zero state-root fallback; simple hash leaf position; basic state fallback |
| `C-CLI-UTXO-001` | P1 | opus | `csv-cli` | `src/commands/sanads.rs` | skip on-chain UTXO validation |
| `E-WALLET-SIGNER-001` | P1 | opus | `csv-wallet` | `src/wallet.rs` | placeholder public key; `get_signer` returns `None` |
| `D-SIG-MLDSA-001` | P1 | opus | `csv-protocol` | `src/signature.rs` | ML-DSA placeholder derivation / feature boundary |
| `B-SDK-CAPABILITY-001` | P2 | sonnet | `csv-sdk` | `src/sanads.rs`, `src/wallet.rs` | SDK feature-not-enabled/fallback signing placeholders |

## Additional backlog from current scan

| Ticket | Status | Priority | Crate | File(s) | Current marker(s) / scope |
|---|---|---|---|---|---|
| `A-SUI-OPS-002` | split | P1 | `csv-adapters/csv-sui` | `src/ops.rs` | balance assumes all available; sender extraction simplified; sequence number `0`; simplified execution; non-empty tx check; digest/checkpoint placeholders. Split by function. |
| `A-SUI-SEAL-003` | split | P1 | `csv-adapters/csv-sui` | `src/seal_protocol.rs` | placeholder sanad/commitment/state-root vectors; empty additional data/proofs; empty digest. Split proof construction vs state reading. |
| `A-SUI-DEPLOY-001` | index-only | P2 | `csv-adapters/csv-sui` | `src/deploy.rs` | deterministic hash fallback for transaction effects; simplified module extraction. |
| `A-APTOS-RUNTIME-002` | index-only | P1 | `csv-adapters/csv-aptos` | `src/runtime_adapter.rs` | empty signatures in proof bundle; registry returns available without on-chain check. |
| `A-APTOS-SEAL-003` | split | P1 | `csv-adapters/csv-aptos` | `src/seal_protocol.rs` | DAGSegment placeholder; placeholder version; empty signatures parsed from DAG bytes. |
| `A-APTOS-WALLET-004` | index-only | P2 | `csv-adapters/csv-aptos` | `src/wallet_operations.rs` | placeholder balance/signing comments. Decide if adapter wallet ops are production or deprecated. |
| `A-BTC-OPS-001` | index-only | P2 | `csv-adapters/csv-bitcoin` | `src/ops.rs` | fail-closed prevout amount API; keystore integration required. |
| `A-BTC-STATE-002` | index-only | P1 | `csv-adapters/csv-bitcoin` | `src/ops.rs`, `src/seal_protocol.rs` | simplified state query; proof with just block hash. |
| `A-BTC-ADAPTER-003` | split | P1 | `csv-adapters/csv-bitcoin` | `src/adapter_impl.rs` | placeholder `Ok(true)`, zero hash mint/broadcast/status placeholders. Security-critical if still reachable. |
| `A-ETH-OPS-002` | index-only | P2 | `csv-adapters/csv-ethereum` | `src/ops.rs` | metadata recorded at lock time; simplified `getSanadState`; placeholder state. |
| `A-ETH-MINT-003` | verify-first | P1 | `csv-adapters/csv-ethereum` | `src/mint.rs` | proof/state root zero/default fields may be test scaffolding or real path; inspect reachability. |
| `A-CEL-SEAL-001` | split | P1 | `csv-adapters/csv-celestia` | `src/seal_protocol.rs` | zero block/tx/row/data roots; placeholder commitment; empty signatures; rollback accepted without validation. |
| `C-CLI-SANADS-002` | index-only | P2 | `csv-cli` | `src/commands/sanads.rs` | simple Merkle root; policy file log-only; lifecycle events placeholder; zero default policy hashes. |
| `C-CLI-WALLET-003` | index-only | P2 | `csv-cli` | `src/commands/wallet/mod.rs` | index `0` TODO for derivation path tracking. |
| `D-REORG-001` | index-only | P1 | `csv-protocol` | `src/reorg/reconciliation.rs` | reconciliation verifies block existence and returns success if block exists. Needs adversarial finality/reorg review. |
| `D-P2P-001` | index-only | P2 | `csv-p2p` | `src/proof_delivery.rs` | relay configured but no relay backend implemented. |
| `D-DAG-001` | verify-first | P2 | `csv-protocol` | `src/seal_protocol.rs` | `transition_dag: Vec<u8>` simplified representation. May require type-level design, not a quick patch. |
| `D-VERSION-001` | verify-first | P3 | `csv-protocol` | `src/version.rs` | simplified-to-full transfer status mapping. Confirm lossy mapping is intended and documented. |
| `E-KEYS-BIP44-001` | index-only | P1 | `csv-keys` | `src/bip44.rs` | derives directly from seed + path components. Validate against real BIP44/SLIP-0010 expectations per chain. |
| `E-SDK-TRANSFERS-002` | index-only | P1 | `csv-sdk` | `src/transfers.rs` | placeholder zero transfer ID fallback. |
| `G-STORE-001` | verify-first | P3 | `csv-store` | `src/lib.rs` | legacy placeholder module note. Likely documentation/deprecation, not security-critical. |

## Items from old REMAINING_TASKS that look already resolved in uploaded snapshot

These should not become implementation tickets unless a fresh scan proves otherwise:

| Area | Why not ticketed now |
|---|---|
| Solana runtime adapter five TODOs | Current `csv-adapters/csv-solana/src/runtime_adapter.rs` appears mostly implemented; only a smaller instruction-format simplification may remain. |
| Aptos `anchor.rs` BLS/Merkle placeholder | Current snapshot appears to contain real aggregation/verification logic. Re-check before reopening. |
| CLI content encryption fake nonce | Current `csv-cli/src/commands/content.rs` appears to use real AES-256-GCM nonce generation/encryption. Re-check before reopening. |
| Contract ABI pinned hash enforcement | Current contract binding code appears to enforce pinned hashes. Re-check with tests. |

## How to create a detailed ticket from an index-only row

1. Copy `development/agent-workflow/TICKET_TEMPLATE.md` to `development/tickets/<ID>.md`.
2. Fill `target_file`, exact `target_patterns`, and scoped `verify_commands`.
3. Add one or two `interface_files`; do not paste the repo.
4. Generate a context pack:

```bash
python3 development/agent-workflow/generate_context_pack.py \
  development/tickets/<ID>.md
```

5. Paste only the generated context pack into the agent session.
