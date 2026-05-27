# Workstream B — csv-core Elimination Progress Tracker

> Status: Pending
> Goal: Remove legacy csv-core crate by migrating all modules to appropriate target crates

## Tasks

### B-1 — Map remaining csv-core modules to target crates
- [ ] Verify module mapping table is complete
- [ ] Confirm target crates exist for all modules
- [ ] Document any edge cases

### B-2 — Migrate csv-sdk off csv-core
- [ ] Replace all csv_core imports in csv-sdk
- [ ] Move client module to csv-sdk/src/client.rs
- [ ] Move wallet_types to csv-sdk/src/wallet.rs
- [ ] Remove csv-core dependency from csv-sdk/Cargo.toml
- [ ] Verify csv-sdk builds

### B-3 — Guard via architecture tests
- [ ] Add nothing_new_depends_on_csv_core test
- [ ] Verify test passes before deletion
- [ ] Add to CI

### B-4 — Delete csv-core
- [ ] Remove from workspace members in root Cargo.toml
- [ ] Delete csv-core directory
- [ ] Create csv-core/TOMBSTONE.md in git history

## Module Mapping

| csv-core module | Target crate | Status |
|-----------------|--------------|--------|
| client | csv-sdk/src/client.rs | Pending |
| consignment | csv-wire/src/consignment.rs | Pending |
| transition | csv-protocol/src/transition.rs | Partial |
| store/state_store | csv-storage | Pending |
| recovery_engine | csv-coordinator/src/recovery/ | Pending |
| trust_package | csv-verifier/src/trust.rs | Pending |
| validator | csv-verifier/src/validator.rs | Exists |
| mcp | csv-mcp-server (TS) | Pending |
| performance | csv-observability | Pending |
| adapter | csv-protocol/src/backend.rs | Exists |
| certification | csv-proof/src/certification.rs | Exists |
| collections | csv-algebra (inline) | Pending |
| compatibility | csv-protocol/src/version.rs | Pending |
| wallet_types | csv-sdk/src/wallet.rs | Pending |
| zk_proof | csv-verifier | Pending |
| data_authority | csv-protocol | Pending |
| runtime_health | csv-observability | Pending |

## Notes

- csv-sdk is the last direct dependent of csv-core
- After B-2, verify with B-3 test before B-4
