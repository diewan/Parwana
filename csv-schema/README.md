# csv-schema

Schema definitions for Parwana data structures.

## Overview

`csv-schema` provides schema definitions for Parwana data structures, enabling validation and documentation of protocol types.

## Key Features

- **Type schemas**: Schema definitions for protocol types
- **Validation**: Schema validation for data structures
- **Documentation**: Self-documenting type definitions
- **Versioning**: Schema version management

## Architecture Role

`csv-schema` provides:

- Type definitions for protocol data structures
- Validation rules for data integrity
- Documentation for protocol types
- Schema evolution support

## Dependencies

- `serde`: Serialization
- `schemars`: JSON schema generation (optional)

## Usage Example

```rust
use csv_schema::MyProtocolType;

let data = MyProtocolType { /* ... */ };
let schema = data.schema();
let is_valid = schema.validate(&data)?;
```

## Design Principles

- **Explicit**: All types have explicit schemas
- **Validated**: Data must conform to schemas
- **Documented**: Schemas serve as documentation
- **Versioned**: Schemas support evolution

## License

MIT OR Apache-2.0
