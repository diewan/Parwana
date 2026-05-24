# CSV Protocol - Stub/Placeholder Elimination

## EventStore Wiring
- [ ] Wire self.event_store.append() into every phase transition in execute()
- [ ] Fix proof_hash from [0u8; 32] to real proof_hash throughout execute()
- [ ] Fix checkpoint data payloads from vec![] to real serialized state
- [ ] Fix signature scheme from hardcoded Secp256k1 to real scheme

## Config & Linting
- [ ] Add workspace-level clippy lints to root Cargo.toml
- [ ] Populate per-crate clippy.toml files

## Comments & TODOs
- [ ] Fix Transfer persistence TODO with actual implementation
- [ ] Fix Rollback TODO with actual rollback call