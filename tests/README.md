# Workspace integration tests

Protocol constitution tests run via:

- `cargo test -p csv-protocol --test protocol_constitution`
- `cargo test -p csv-runtime --test protocol_constitution`

The files under `tests/protocol_constitution/` mirror the runtime test modules for documentation and CI reference; execute the crate targets above for authoritative runs.
