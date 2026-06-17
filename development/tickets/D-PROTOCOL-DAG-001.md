---
id: D-PROTOCOL-DAG-001
title: "Replace Vec<u8> DAG representation with typed structure in SealProtocol trait"
theme: D
crate: csv-protocol
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-protocol/src/seal_protocol.rs
target_patterns:
  - "transition_dag: Vec<u8>, // Simplified DAG representation"
interface_files:
  - csv-protocol/src/proof_bundle.rs
  - csv-protocol/src/anchor.rs
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

The `SealProtocol::build_proof_bundle` trait method accepts `transition_dag: Vec<u8>` as a parameter, documented as "Simplified DAG representation". This is a raw byte blob with no type-level structure, making it impossible to validate, serialize canonically, or reason about at the type level.

## Why it matters

The DAG represents state transitions between anchors. Using `Vec<u8>` means:
- No compile-time validation of DAG structure
- No canonical encoding for deterministic proof generation
- Each adapter must invent its own encoding format
- No way to verify DAG integrity without adapter-specific knowledge

## Task

Define a typed `DagSegment` struct in `csv-protocol` that replaces `Vec<u8>`. The struct should contain at minimum:
- `anchor_from`: the source anchor reference
- `anchor_to`: the destination anchor reference
- `transition_data`: the canonical transition payload (can be `Vec<u8>` for now, but typed)
- `proof`: inclusion proof bytes (can be `Vec<u8>` for now)

Update the `SealProtocol` trait to use `DagSegment` instead of `Vec<u8>`. Update all adapter implementations to construct `DagSegment` from their chain-specific data.

## Acceptance criteria

- [ ] `DagSegment` struct is defined in `csv-protocol` with typed fields
- [ ] `SealProtocol::build_proof_bundle` signature uses `DagSegment` instead of `Vec<u8>`
- [ ] All adapter implementations compile with the new signature
- [ ] `DagSegment` implements `CanonicalEncoding` for deterministic serialization
- [ ] `cargo check -p csv-protocol` passes
- [ ] `cargo test -p csv-protocol` passes

## Notes

This is a type-level design change. The `Vec<u8>` field is at line 281 of `seal_protocol.rs`. Keep the struct minimal — the full DAG type system can be expanded later. The goal is to replace the untyped blob with a typed container.
