---
id: REPOSPLIT-CONTRACTS-010
title: "Pilot extraction of contracts and reproducibly generated Rust bindings"
theme: multi-repo-contracts-pilot
crate: csv-contract-bindings
priority: P2
security_critical: true
model_hint: opus
status: blocked
context_radius: 40
agent_md: .agents/AGENT.md
target_file: csv-contract-bindings/src/lib.rs
target_patterns:
  - "mod"
  - "pub use"
target_file_2: csv-contract-bindings/Cargo.toml
target_patterns_2:
  - "csv-contract-bindings"
interface_files:
  - csv-contracts/rust-toolchain.toml
  - deployments/README.md
  - csv-docs/contracts/REGISTRY_VERIFICATION_WIRING.md
reference_crate: csv-contract-bindings
reference_file: csv-contract-bindings/src/abi_constitution.rs
reference_patterns:
  - "ABI"
verify_commands:
  - "cargo test -p csv-contract-bindings"
  - "cd csv-contracts/ethereum/contracts && forge build"
  - "cd csv-contracts/solana/contracts && NO_DNA=1 anchor build"
  - "cd csv-contracts/sui && sui move build"
  - "cd csv-contracts/aptos/contracts && aptos move compile"
forbidden_patterns:
  - "manual binding edit"
  - "unversioned ABI"
  - "git push --force"
contract_files:
  - csv-contracts/ethereum/contracts/src/CSVSeal.sol
  - csv-contracts/solana/contracts/idl/csv_seal.json
  - csv-contracts/sui/sources/csv_seal.move
  - csv-contracts/aptos/contracts/sources/csv_seal.move
cross_boundary_check: true
---

## Problem

Contracts use distinct language toolchains and deployment lifecycles, making
them the best first extraction candidate. However, bindings, ABI/IDL
constitution checks, deployment metadata, build scripts, and submodule state
must move as one reproducible release unit. The virtual-boundary rehearsal has
not yet approved this extraction.

## Why it matters

Contract bytecode and client bindings authorize security-critical mint,
settlement, replay, and verifier behavior. A mismatch between released
contracts and bindings can invalidate verification or submit incorrect calls.

## Task

After `REPOSPLIT-BOUNDARY-009` records a go decision, extract contract sources
with relevant history into `csv-contracts`. Generate and release immutable
ABIs/IDLs, bytecode/interface checksums, deployment metadata, and Rust bindings
from the same tagged source. Update the Rust workspace to consume a versioned
binding release.

## Acceptance criteria

- [ ] The boundary rehearsal explicitly unblocks this ticket.
- [ ] Ethereum, Solana, Sui, and Aptos contract builds/tests pass in the extracted repository.
- [ ] Compiler and contract toolchain versions are pinned.
- [ ] Bindings are generated reproducibly and match released interfaces/bytecode.
- [ ] The Rust workspace consumes tagged bindings without a sibling source path.
- [ ] Existing deployment addresses, network metadata, provenance, licenses, and history are preserved.
- [ ] A coordinated contract/binding security release and rollback procedure is tested.
- [ ] The pilot remains healthy for one release cycle before another repository is extracted.

## Notes

Status is `blocked` by design. Do not begin physical extraction until every
prerequisite in `TICKETS_INDEX.md` is complete and the rehearsal says go.
