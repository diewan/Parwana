# Workstream A — csv-wire Activation Progress Tracker

> Status: In Progress
> Goal: Ensure all serde/transport encoding is routed through csv-wire, not direct derives in L0-L4 crates

## Tasks

### A-1 — Audit current serde surface
- [x] Run grep audit on csv-protocol, csv-hash, csv-proof, csv-verifier, csv-codec
- [x] Produce migration manifest grouped by type name
- [ ] Review manifest with team

### A-2 — Define wire-boundary types in csv-wire
- [x] ProofBundleWire (already started)
- [x] SealPointWire
- [x] Transfer state Wire types (Locked, AwaitingFinality, ProofBuilding, ProofValidated)
- [x] Hash primitives Wire types (Hash, SanadId, Commitment)
- [ ] RPC chain types (bitcoin, ethereum, solana, aptos)

### A-3 — Strip serde from L0–L4 internal types
- [ ] Remove Serialize/Deserialize derives from all internal types
- [ ] Remove serde from Cargo.toml deps in L0-L4 crates
- [ ] Add transitional cfg_attr gates if needed for tests

### A-4 — Wire chain-adapter RPCs through csv-wire
- [ ] Bitcoin RPC types
- [ ] Ethereum RPC types
- [ ] Solana RPC types
- [ ] Aptos RPC types

### A-5 — Enforce via deny.toml
- [ ] Add cargo-deny rule for serde wrappers
- [ ] Add architecture guard test for l1_to_l4_crates_do_not_directly_import_serde
- [ ] Verify both checks pass

## Notes

- Pattern reference: `csv-wire/src/canonical.rs` for CanonicalProof → CanonicalProofWire
- All *Wire types must: derive Serialize/Deserialize, implement From/Internal and TryFrom<Wire> for Internal, hex-encode byte arrays
