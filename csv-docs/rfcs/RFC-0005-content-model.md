# RFC-0005: Content Model

## Status

Proposed

## Motivation

Current Sanad model is too weakly typed for complex content:

- Optimized for hashes, commitments, ownership transfer
- Not for rich semantic content, structured metadata, embedded claims
- No support for:
  - Merkleized content trees
  - Selective disclosure
  - Encrypted subtrees
  - Streaming verification
  - Attachment references
  - Schema evolution

Without canonicalization, complex Sanads will fracture verification ecosystems.

## Proposed Change

### 1. Replace Flat Sanad Content

DELETE:

```rust
struct Sanad {
    payload: Vec<u8>
}
```

### 2. Introduce Merkleized Content Trees

```rust
pub struct Sanad {
    header: SanadHeader,
    content_root: ContentRoot,
    proof_root: ProofRoot,
    schema_id: SchemaId,
    encoding_id: EncodingId,
    attachment_root: AttachmentRoot,
}
```

### 3. Create Content Tree System

Create `/crates/csv-content/` with:

- `content_tree.rs` - Merkleized content structure
- `claims.rs` - Structured claims
- `attachments.rs` - Attachment references
- `rights.rs` - Composable rights
- `participants.rs` - Multi-party state
- `encryption.rs` - Encryption envelopes
- `redaction.rs` - Redacted subtrees
- `streaming.rs` - Streaming verification

### 4. Add Selective Disclosure Proofs

MANDATORY:

```rust
DisclosureProof
RedactedMerkleProof
EncryptedSubtreeProof
```

Users must prove subtree validity without exposing whole content.

### 5. Add Attachment Model

NEVER store large blobs directly in Sanads:

```rust
pub struct AttachmentRef {
    cid: ContentAddress,
    media_type: MediaType,
    size: u64,
    hash: ContentHash,
}
```

### 6. Add Resource Accounting

Every verification path MUST calculate:

```rust
VerificationCost {
    cpu,
    memory,
    io,
    recursion_depth,
}
```

Reject pathological content.

## Rationale

Merkleized content trees enable:

- Efficient verification of large content
- Selective disclosure
- Streaming validation
- Partial updates
- Schema evolution

## Impact

BREAKING CHANGE: Complete Sanad redesign.

- Update all Sanad construction
- Update all verification logic
- Update serialization
- Migration path for existing Sanads

## Alternatives

- Keep flat Sanad content (REJECTED - doesn't scale)
- Use ad hoc content structures (REJECTED - not canonical)

## Unresolved Questions

- Content address format (IPFS, custom)?
- Schema evolution strategy?
- Attachment storage layer?
