---
id: SOL-SYNC-DECODE-001
title: "Background sync does not decode or filter transactions against the CSV program ID"
theme: "Solana adapter background sync/indexer"
crate: csv-solana
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-solana/src/sync_coordinator.rs"
target_patterns:
  - "async fn process_slot"
  - "TODO: Implement proper transaction filtering by decoding EncodedTransaction"
  - "_csv_program_id: solana_sdk::pubkey::Pubkey"
interface_files:
  - "csv-contracts/solana/contracts/programs/csv-seal/src/instructions.rs"
  - "csv-contracts/solana/contracts/programs/csv-seal/src/lib.rs"
  - "csv-adapters/csv-solana/src/runtime_adapter.rs"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-solana --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-solana --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files:
  - "csv-contracts/solana/contracts/programs/csv-seal/src/instructions.rs"
cross_boundary_check: false
---

## Problem

`SyncCoordinator::process_slot` (`csv-adapters/csv-solana/src/sync_coordinator.rs:296-324`)
fetches each block but never decodes or filters its transactions:

```rust
async fn process_slot(
    rpc: &Arc<dyn SolanaRpc>,
    slot: u64,
    _csv_program_id: solana_sdk::pubkey::Pubkey,
) -> SolanaResult<()> {
    let block = rpc.get_block(slot)...?;

    if let Some(block_data) = block {
        // Process transactions relevant to CSV
        // Filter for transactions involving the CSV program
        // For now, just log the number of transactions
        // Proper transaction filtering requires decoding the encoded transaction
        tracing::debug!(
            "Processing slot {} with {} transactions",
            slot,
            block_data.transactions.len()
        );

        // TODO: Implement proper transaction filtering by decoding EncodedTransaction
        // and checking account keys against csv_program_id
    } else {
        tracing::debug!("Slot {} not found or empty", slot);
    }

    Ok(())
}
```

`csv_program_id` is received but prefixed with `_` (unused) — the function
logs a transaction count per slot and does nothing further. It cannot
identify which, if any, transactions in a block are actually CSV protocol
transactions, so nothing downstream of this function can act on real
protocol events observed via background sync.

## Why it matters

This is peripheral to the tested mint/lock transfer path, which uses a
separately-implemented, tested `confirm_tx` in
`csv-adapters/csv-solana/src/runtime_adapter.rs` (see
`confirm_tx_returns_confirmed_slot`) — this ticket does not block live
transfers. It does block any indexer/monitoring feature that depends on this
sync loop actually identifying protocol-relevant activity (e.g., a future
`csv sanad list --chain solana --live` or an operator dashboard watching for
unexpected on-chain seal activity).

## Task

- Decode each transaction in the fetched block (`block_data.transactions`,
  `EncodedTransaction`) and filter to those whose account keys include
  `csv_program_id` (drop the `_` prefix on the parameter once it is used).
- Use the Anchor instruction discriminators from the on-chain program
  (`csv-contracts/solana/contracts/programs/csv-seal/src/instructions.rs`) to
  further classify which CSV instruction each relevant transaction invoked,
  where that is useful for the sync coordinator's downstream consumers.
- Surface the identified protocol-relevant transactions (return them, emit an
  event, or feed them to whatever downstream consumer this sync loop is meant
  to serve — check for an existing hook/channel in `sync_coordinator.rs`
  before inventing a new one).

## Acceptance criteria

- [ ] `process_slot` decodes transactions in a fetched block and filters to
      those touching `csv_program_id`.
- [ ] Identified protocol-relevant transactions are surfaced to whatever
      downstream consumer this sync loop serves (not just logged).
- [ ] Test with a fixture slot/block containing both CSV-relevant and
      irrelevant transactions, asserting only the relevant ones are surfaced.
- [ ] All `verify_commands` pass.

## Notes

The tested cross-chain mint/lock transfer flow does not depend on this sync
loop — `runtime_adapter.rs::confirm_tx` is the separately-implemented,
tested path used there. Do not conflate the two while fixing this.
