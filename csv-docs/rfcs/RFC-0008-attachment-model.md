# RFC-0008: Attachment Model with Resource Accounting

**Status:** Proposed
**Author:** CSV Protocol Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC defines an attachment model for Sanads that enables attaching metadata, proofs, and references to Sanads with resource accounting to prevent abuse.

## Motivation

The current protocol has no mechanism for attaching additional data to Sanads. This limits:

1. **Metadata association** — Cannot attach descriptive metadata to Sanads
2. **Proof chaining** — Cannot attach verification proofs to Sanads
3. **Resource limits** — No accounting for attachment size/cost
4. **Attachment validation** — No framework for validating attachments

## Design

### 1. Attachment Types

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachmentType {
    Metadata,      // Descriptive metadata
    Proof,         // Verification proof
    Reference,     // Reference to external resource
    Policy,        // Policy rule
    Custom(u16),   // Custom type
}
```

### 2. Attachment Structure

```rust
pub struct Attachment {
    pub id: Hash,
    pub attachment_type: AttachmentType,
    pub data: Vec<u8>,
    pub size_bytes: usize,
    pub hash: Hash,  // Hash of (type || data)
}

impl Attachment {
    pub const MAX_SIZE: usize = 4096;
    
    pub fn new(attachment_type: AttachmentType, data: Vec<u8>) -> Result<Self, ProtocolError> {
        if data.len() > Self::MAX_SIZE {
            return Err(ProtocolError::AttachmentTooLarge {
                expected: Self::MAX_SIZE,
                got: data.len(),
            });
        }
        let hash = csv_tagged_hash(
            format!("csv.attachment.{}", attachment_type as u16).leak(),
            &data,
        );
        Ok(Self {
            id: hash,
            attachment_type,
            data,
            size_bytes: data.len(),
            hash,
        })
    }
}
```

### 3. Resource Accounting

```rust
pub struct AttachmentBudget {
    pub max_total_bytes: usize,
    pub max_attachments: usize,
    pub max_metadata_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_reference_bytes: usize,
    pub max_policy_bytes: usize,
}

impl AttachmentBudget {
    pub const DEFAULT: Self = Self {
        max_total_bytes: 16384,
        max_attachments: 10,
        max_metadata_bytes: 4096,
        max_proof_bytes: 8192,
        max_reference_bytes: 2048,
        max_policy_bytes: 2048,
    };
}
```

### 4. Sanad with Attachments

```rust
pub struct SanadWithAttachments {
    pub sanad: Sanad,
    pub attachments: Vec<Attachment>,
    pub attachment_root: Hash,  // Merkle root of attachment hashes
    pub budget: AttachmentBudget,
}

impl SanadWithAttachments {
    pub fn add_attachment(&mut self, attachment: Attachment) -> Result<(), ProtocolError> {
        // Check budget constraints
        // Check attachment count
        // Check per-type size limits
        // Add attachment and update root
    }
}
```

## Implementation

### Changes to `csv-core/src/sanad.rs`

- Add `Attachment` type
- Add `AttachmentBudget` type
- Add `SanadWithAttachments` type
- Add attachment validation in `Sanad.verify()`

### New Module: `csv-core/src/attachment.rs`

- `Attachment` implementation
- `AttachmentBudget` enforcement
- `AttachmentRoot` computation

## Security Impact

- **Resource limits** — Budget enforcement prevents attachment-based DoS
- **Type safety** — Attachment types are enforced at compile time
- **Integrity** — Attachment root ensures all attachments are included

## References

- Protocol Constitution Section 13 — Sanads
- `csv-core/src/sanad.rs` — Current Sanad implementation
