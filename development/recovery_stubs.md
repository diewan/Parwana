# Workstream C — Phase-Specific Crash Recovery Progress Tracker

> Status: Pending
> Goal: Implement proper crash recovery for all transfer phases instead of falling back to full re-execution

## Tasks

### C-1 — execute_from_lock (LockConfirmed recovery)
- [ ] Load LockConfirmed journal entry
- [ ] Reconstruct Locked typestate from journal payload
- [ ] Resume at AwaitingFinality phase
- [ ] Add block_height and tx_hash_bytes to ExecutionJournalEntry

### C-2 — execute_from_proof (ProofValidated recovery)
- [ ] Load proof bytes from journal
- [ ] Skip proof generation, go straight to mint
- [ ] Add proof_payload to ExecutionJournalEntry

### C-3 — AwaitingFinality recovery
- [ ] Re-poll finality monitor with proof height from journal
- [ ] Add get_confirmation_count to AdapterRegistry trait
- [ ] Resume to ProofBuilding when finality achieved

### C-4 — ProofBuilding recovery (intermediate progress)
- [ ] Check for persisted proof-in-progress checkpoint
- [ ] Resume from checkpoint if exists
- [ ] Add TransferPhase::ProofBuildingCheckpoint enum variant
- [ ] Implement periodic checkpointing in proof engine

### C-5 — Wire proof_payload into ExecutionJournalEntry
- [ ] Add block_height: u64 field
- [ ] Add tx_hash_bytes: Vec<u8> field
- [ ] Add proof_payload: Option<Vec<u8>> field
- [ ] Create SQL migration 0002_journal_payload.sql

## Notes

- execution_journal already records phase transitions with Entered/Completed/Failed
- Missing piece: execute_from_* methods must read journal state and skip completed phases
- C-5 unblocks F-4 (recovery test coverage gate)
