# csv-content

Content types for CSV Protocol.

## Overview

`csv-content` provides content type definitions and handling for the CSV protocol, including supported content formats and validation.

## Key Features

- **Content types**: Definitions for supported content types
- **Validation**: Content validation rules
- **Metadata**: Content metadata handling
- **Encoding**: Content encoding/decoding

## Architecture Role

`csv-content` provides:

- Type-safe content handling
- Content validation
- Metadata management
- Encoding support

## Dependencies

- `serde`: Serialization
- `thiserror`: Error handling

## Usage Example

```rust
use csv_content::{ContentType, Content};

let content = Content {
    content_type: ContentType::Json,
    data: vec![/* ... */],
    metadata: /* ... */,
};

let is_valid = content.validate()?;
```

## Design Principles

- **Type-safe**: Strongly typed content
- **Validated**: Content must pass validation
- **Extensible**: Support for new content types
- **Metadata-rich**: Rich metadata support

## License

MIT OR Apache-2.0
