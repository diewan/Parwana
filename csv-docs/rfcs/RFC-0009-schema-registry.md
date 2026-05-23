# RFC-0009: Schema Registry

## Status

Proposed

## Motivation

Current wallet and CLI architecture lacks:

- Schema registry
- Dynamic renderer system
- Typed plugin system
- Partial content verification
- Streaming attachment verification
- Schema evolution strategy
- Canonical content negotiation

If Sanads become complex, wallet performance will collapse and verification latency will explode.

## Proposed Change

### 1. Create Schema Registry

Create `/crates/csv-schema/` with:

- Schema definitions
- Schema validation
- Schema versioning
- Schema evolution
- Schema migration

### 2. Define Schema Lifecycle

```rust
pub enum SchemaStatus {
    Proposed,
    Accepted,
    Deprecated,
    Rejected,
}

pub struct Schema {
    id: SchemaId,
    version: SchemaVersion,
    status: SchemaStatus,
    definition: SchemaDefinition,
}
```

### 3. Add Schema Governance

Create `/docs/governance/schema-governance.md` defining:

- Schema lifecycle
- Schema deprecation
- Schema compatibility
- Schema IDs
- Schema migration

### 4. Create Schema Plugin System

Complex Sanads require:

```rust
trait SchemaRenderer {
    fn render(&self, content: &Content) -> RenderedView;
    fn validate(&self, content: &Content) -> ValidationResult;
    fn sanitize(&self, content: &mut Content) -> SanitizedContent;
}
```

### 5. Add Schema Evolution Strategy

Define:

- Schema versioning rules
- Backward compatibility
- Migration paths
- Deprecation timeline

## Rationale

Schema registry enables:

- Dynamic content rendering
- Schema evolution
- Type-safe validation
- Plugin architecture
- Long-term compatibility

## Impact

BREAKING CHANGE: Schema system redesign.

- Create schema registry
- Update wallet UI
- Update CLI
- Add schema tests
- Migration path for existing content

## Alternatives

- Keep ad hoc schemas (REJECTED - doesn't scale)
- No schema evolution (REJECTED - impractical)

## Unresolved Questions

- Schema ID format?
- Schema governance process?
- Migration tooling?
