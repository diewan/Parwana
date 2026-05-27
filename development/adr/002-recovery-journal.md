# ADR 002: Execution Journal for Crash Recovery

## Status

Accepted

## Context

The CSV Protocol runtime needs to recover transfers from arbitrary crash points. The current implementation has four recovery paths that fall back to full re-execution instead of resuming at the correct phase. The `execution_journal` already records phase transitions with `Entered/Completed/Failed`, but the journal entry schema lacks the necessary payload fields to reconstruct transfer state.

## Decision

Extend the `ExecutionJournalEntry` schema to include:
- `block_height: u64` - for lock/proof height tracking
- `tx_hash_bytes: Vec<u8>` - for transaction identification
- `proof_payload: Option<Vec<u8>>` - for proof bytes or checkpoint data

Each `execute_from_*` method must read journal state and skip already-completed phases.

### Schema

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionJournalEntry {
    pub transfer_id: String,
    pub phase: TransferPhase,
    pub status: JournalStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub block_height: u64,              // NEW
    pub tx_hash_bytes: Vec<u8>,         // NEW
    pub proof_payload: Option<Vec<u8>>, // NEW
}
```

### Recovery Paths

1. **LockConfirmed**: Load lock result from journal, skip lock broadcast, resume at proof generation
2. **ProofValidated**: Load proof bytes from journal, skip proof generation, go straight to mint
3. **AwaitingFinality**: Re-poll finality monitor with proof height from journal
4. **ProofBuilding**: Check for persisted checkpoint, resume if exists, else restart from lock

## Consequences

### Positive
- True crash recovery at any phase
- No redundant work after restart
- Journal provides complete audit trail
- Enables checkpointing for long-running operations

### Negative
- Journal storage overhead increases
- More complex recovery logic
- Need to handle journal corruption cases

## Enforcement

- Architecture guard test verifies all transfer phases have crash recovery tests
- CI requires crash_recovery test suite to pass
- SQL migration required for existing deployments

## References

- Workstream C in csv_migration_plan.md
- csv-runtime/src/execution_journal.rs
