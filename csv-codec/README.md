# csv-codec

Canonical serialization, deterministic decoding, schema validation, and byte ordering for CSV Protocol.

## Overview

`csv-codec` provides canonical CBOR serialization for the CSV protocol. All protocol-critical data must be serialized using this crate to ensure determinism and cross-chain compatibility.

## Key Features

- **Canonical CBOR encoding**: Deterministic serialization for protocol state
- **Little-endian byte ordering**: Consistent integer encoding across platforms
- **Schema validation**: Type and structure validation
- **Version tags**: Protocol versioning support
- **Checksum support**: Data integrity verification
- **No floats**: Protocol state uses only integer types

## Canonical Encoding Rules

- Little endian ONLY for all integer types
- Fixed field ordering (lexicographic for maps)
- Explicit enum tags
- Explicit version tags
- Deterministic maps/arrays (sorted keys)
- Canonical UTF-8 (NFC normalized, no BOM)
- No floats in protocol state

## Modules

- **byte_order**: Byte ordering utilities (little-endian)
- **canonical**: Canonical CBOR encoding/decoding functions
- **decode**: Deterministic decoding
- **encode**: Canonical encoding
- **error**: Codec error types
- **schema**: Schema validation
- **versioning**: Protocol version management

## Architecture Role

`csv-codec` is the serialization layer that:
- Ensures deterministic encoding across all implementations
- Provides canonical CBOR for protocol state persistence
- Validates data structures against schemas
- Supports protocol versioning through tags

## Dependencies

- `ciborium`: CBOR serialization
- `thiserror`: Error handling

## Usage Example

```rust
use csv_codec::{to_canonical_cbor, from_canonical_cbor};

// Serialize to canonical CBOR
let data = MyProtocolType { /* ... */ };
let bytes = to_canonical_cbor(&data)?;

// Deserialize from canonical CBOR
let decoded: MyProtocolType = from_canonical_cbor(&bytes)?;
```

## Design Principles

- **Determinism**: Same data always produces same bytes
- **Cross-platform**: Works identically on all architectures
- **Validation**: Rejects malformed data early
- **Versioning**: Supports protocol evolution

## License

MIT OR Apache-2.0
