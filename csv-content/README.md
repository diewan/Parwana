# csv-content

Content types for CSV Protocol — Merkle trees, selective disclosure, encryption, and content integrity.

## Overview

`csv-content` provides content type definitions, Merkle tree operations, and selective disclosure for the CSV protocol. It enables content commitment, proof generation, and privacy-preserving disclosure.

## Key Features

- **Merkle trees**: Content tree construction and verification
- **Selective disclosure**: Prove subset of content without revealing all
- **Encryption**: Subtree encryption with key management
- **Attachments**: File attachment references with media types
- **Participants**: Role-based participant management
- **Claims**: Content claims with predicates and descriptions
- **Resource accounting**: Verification cost estimation

## Architecture Role

`csv-content` provides:

- `ContentTree` — Merkleized content structure
- `ContentProof` — Merkle inclusion proofs
- `DisclosureProof` — Selective disclosure with subtree roots
- `AttachmentRef` — File attachment references with `MediaType`
- `Participant` — Role-based participants with `ParticipantRole`
- `Claim` — Content claims with `ClaimPredicate`
- `EncryptionDescriptor` / `EncryptionEnvelope` — Subtree encryption
- `KeyAccess` — Key access management
- `VerificationLimit` — Resource accounting for verification

## Dependencies

- `serde`: Serialization (via csv-wire boundary)
- `thiserror`: Error handling
- `csv-hash`: Hash types for Merkle operations

## Usage Example

```rust
use csv_content::content_tree::ContentTree;
use csv_content::addressing::compute_content_address;

// Create a content tree
let tree = ContentTree::from_leaves(vec![
    b"Hello World".to_vec(),
    b"This is a test".to_vec(),
]);

// Generate a Merkle proof
let proof = tree.prove(0)?;

// Verify inclusion
assert!(proof.verify(&tree.root_hash()));

// Create selective disclosure
let disclosure = tree.disclose(&[0, 2])?;
```

## Design Principles

- **Type-safe**: Strongly typed content structures
- **Validated**: All content must pass validation
- **Extensible**: Support for new content types and predicates
- **Metadata-rich**: Rich metadata and participant support
- **Privacy-preserving**: Selective disclosure without full content exposure
- **Chain-agnostic**: No chain adapter dependencies

## License

MIT OR Apache-2.0
