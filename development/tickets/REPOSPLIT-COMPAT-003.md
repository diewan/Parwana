---
id: REPOSPLIT-COMPAT-003
title: "Define API, protocol, wire-format, and contract compatibility policy"
theme: multi-repo-compatibility
crate: csv-protocol
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-docs/PROTOCOL_CONSTITUTION.md
target_patterns:
  - "Protocol"
  - "version"
target_file_2: csv-wire/src/lib.rs
target_patterns_2:
  - "wire"
interface_files:
  - csv-codec/src/lib.rs
  - csv-proof/src/lib.rs
  - csv-contract-bindings/src/lib.rs
reference_crate: csv-protocol
reference_file: csv-protocol/Cargo.toml
reference_patterns:
  - "version"
verify_commands:
  - "cargo test -p csv-codec -p csv-wire -p csv-proof -p csv-protocol"
  - "cargo test --workspace --doc"
forbidden_patterns:
  - "silent fallback"
  - "accept unknown version"
  - "best effort verification"
contract_files:
  - csv-contracts/ethereum/contracts/src/CSVSeal.sol
  - csv-contracts/solana/contracts/idl/csv_seal.json
cross_boundary_check: true
---

## Problem

Crate dependencies now carry versions, but there is no single normative policy
for compatibility across Rust APIs, canonical CBOR, proof bundles, wire
messages, schema versions, contract events, generated bindings, and deployed
contracts. Independent repositories cannot safely decide upgrades from Cargo
SemVer alone.

## Why it matters

Security and consensus-visible formats must fail closed when incompatible.
Silent downgrade or permissive decoding could create divergent verification,
replay identifiers, or mint authorization semantics.

## Task

Add a normative compatibility policy and matrix. Define version ownership,
supported version combinations, N/N-1 expectations where appropriate,
deprecation windows, coordinated-release triggers, unknown-version rejection,
and emergency security upgrade behavior.

## Acceptance criteria

- [ ] A normative compatibility document exists under `csv-docs/` and is linked from the protocol constitution.
- [ ] Rust API SemVer is distinguished from protocol and wire compatibility.
- [ ] Canonical encoding, proofs, schemas, events, bindings, and deployments each have an explicit version rule.
- [ ] Supported core/runtime/adapter/CLI/contract combinations are tabulated.
- [ ] Unknown or unsupported security-critical versions are required to fail closed.
- [ ] Any missing implementation-level version discriminator is recorded as a separate atomic ticket.
- [ ] Documentation tests and relevant crate tests pass.

## Notes

Do not invent a version field for a hashed structure without defining how it
changes canonical bytes, domain separation, and existing golden vectors.
