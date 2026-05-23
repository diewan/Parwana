# RFC-0001: Canonical Serialization

## Status

Proposed

## Motivation

The current codebase contains ad hoc serialization implementations (`to_vec()`, manual byte pushes, serde_json in protocol paths). This creates:

- Version drift
- Endianness mismatch
- Canonicalization bugs
- Hash collisions through ambiguity
- Inconsistent encoding across languages

This is a protocol security risk and will cause ecosystem divergence.

## Proposed Change

### 1. Delete ALL Ad Hoc Protocol Serialization

Remove all manual serialization from protocol types:

- `BitcoinSealPoint::to_vec`
- `AptosSealPoint::to_vec`
- Any other `to_vec()` implementations in protocol state
- Manual byte array construction in protocol code

### 2. Introduce Canonical Codec Layer

Create `csv-codec` crate with:

- `canonical.rs` - canonical encoding rules
- `encode.rs` - deterministic encoding
- `decode.rs` - deterministic decoding
- `schema.rs` - schema validation
- `versioning.rs` - encoding versioning
- `error.rs` - codec errors

### 3. Define Canonical Encoding Rules

MANDATORY:

- Little endian ONLY for integers
- Fixed field ordering (alphabetical by field name)
- No optional implicit fields
- Explicit enum tags (u8 discriminants)
- Explicit version tags (u16 version fields)
- Deterministic map ordering (sorted by key)
- Deterministic array ordering (no reordering)
- Canonical UTF-8 normalization (NFC)
- NO floating points in protocol state
- Fixed-length arrays where possible
- Varint encoding for variable-length integers

### 4. Choose Canonical Encoding Format

Options:

- DAG-CBOR (recommended)
- Deterministic CBOR
- SSZ (Simple Serialize)
- Canonical protobuf
- Custom fixed binary format

Recommendation: DAG-CBOR for existing CBOR usage + canonical guarantees.

## Rationale

Canonical serialization is the foundation of:

- Deterministic hashing
- Cross-language compatibility
- Protocol stability
- Verification consistency

Without canonical serialization, independent implementations will diverge.

## Impact

BREAKING CHANGE: All existing serialized data must be migrated.

- Update all `to_vec()` calls to use canonical codec
- Update all deserialization to use canonical codec
- Migration path for existing data
- Version bump required

## Alternatives

- Keep ad hoc serialization (REJECTED - too risky)
- Use serde with strict config (REJECTED - not canonical enough)
- Use protobuf (REJECTED - not canonical by default)

## Unresolved Questions

- Which canonical encoding format to choose?
- Migration strategy for existing data?
- Version field placement in all types?
