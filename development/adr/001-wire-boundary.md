# ADR 001: Wire Boundary Architecture

## Status

Accepted

## Context

The CSV Protocol architecture defines `csv-wire` as the sole owner of ALL serde and transport encoding. However, in the current implementation, every crate from L2 up derives `Serialize/Deserialize` directly. This violates the architectural constitution and makes wire-format changes cascade everywhere.

## Decision

All types that cross a wire boundary must have a corresponding `*Wire` mirror type in `csv-wire`. Internal types in L0-L4 crates must NOT derive `Serialize/Deserialize` directly.

### Pattern

For each internal type:
1. Create a `*Wire` type in `csv-wire`
2. The `*Wire` type derives `Serialize, Deserialize` (ONLY in csv-wire)
3. Implement `From<Internal>` and `TryFrom<Wire> for Internal`
4. Hex-encode all `[u8; N]` and `Vec<u8>` fields

### Example

```rust
// csv-wire/src/seal.rs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealPointWire {
    pub seal_bytes: String,   // hex
    pub output_index: Option<u32>,
}

impl From<SealPoint> for SealPointWire {
    fn from(s: SealPoint) -> Self {
        Self {
            seal_bytes: hex::encode(&s.seal_bytes),
            output_index: s.output_index,
        }
    }
}

impl TryFrom<SealPointWire> for SealPoint {
    type Error = String;
    fn try_from(w: SealPointWire) -> Result<Self, Self::Error> {
        Ok(SealPoint::new(
            hex::decode(&w.seal_bytes).map_err(|e| format!("seal_bytes: {e}"))?,
            w.output_index,
        ).map_err(|e| e.to_string())?)
    }
}
```

## Consequences

### Positive
- Wire format changes are isolated to csv-wire
- Internal types remain pure and serialization-free
- Clear boundary between protocol logic and transport encoding
- Easier to test serialization independently

### Negative
- Additional boilerplate for each wire type
- Conversion overhead at boundaries
- More code to maintain

## Enforcement

- `cargo-deny` rule forbids serde as direct dependency for L0-L4 crates
- Architecture guard test verifies no direct serde imports in L0-L4
- CI checks both on every PR

## References

- Workstream A in csv_migration_plan.md
- dep_graph_constitution.rs
