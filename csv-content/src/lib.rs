//! CSV Content - L2: Content tree system
//!
//! **Layer:** L2 (Content and schema types)
//! **Encoding:** MAY use serde or canonical_cbor
//! **Serde Policy:** MAY use serde (serialization is the primary use case)
//!
//! Provides Merkleized content trees, selective disclosure proofs,
//! attachment references, and resource accounting for the CSV protocol.
//!
//! # Architecture
//!
//! - **ContentTree**: Merkleized content tree with selective disclosure
//! - **Claims**: Content claims and rights management
//! - **Attachments**: External attachment reference model
//! - **Participants**: Content participant roles and identities
//! - **Addressing**: Content addressing utilities
//! - **SelectiveDisclosure**: Selective disclosure proofs
//! - **Encryption**: Encryption envelopes for content
//! - **ResourceAccounting**: Verification resource limits
//!
//! # Quick Start
//!
//! ```no_run
//! use csv_content::ContentTree;
//!
//! // Create a content tree
//! let tree = ContentTree::from_leaves(vec![b"leaf-0".to_vec(), b"leaf-1".to_vec()]);
//!
//! // Verify inclusion with the tree's Merkle proof.
//! assert!(tree.verify_inclusion(0, b"leaf-0"));
//! ```
//!
//! # Migration Guide
//!
//! When working with L2 types:
//! - ✅ MAY use serde for serialization
//! - ✅ MAY use canonical_cbor for cross-chain compatibility
//! - No strict encoding requirements for protocol correctness
//!
//! See [csv-docs/LAYERING.md](../../csv-docs/LAYERING.md) for detailed layer information.

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_slicing)]

pub mod addressing;
pub mod attachments;
pub mod claims;
pub mod content_tree;
pub mod encryption;
pub mod participants;
pub mod resource_accounting;
pub mod selective_disclosure;

// Re-exports from content_tree
pub use content_tree::{
    AccessControl, ContentNode, ContentProof, ContentTree,
    DisclosureProof as ContentDisclosureProof,
    EncryptedSubtreeProof as ContentEncryptedSubtreeProof, NodeMetadata, NodeType,
    RedactedMerkleProof as ContentRedactedMerkleProof, VerificationCost, VerificationCostError,
};

// Re-exports from claims
pub use claims::{Claim, ClaimPredicate, ContentRights, RightsTransfer};

// Re-exports from attachments
pub use attachments::{AttachmentBudget, AttachmentRef, MediaType};

// Re-exports from participants
pub use participants::{Participant, ParticipantId, ParticipantRole, ParticipantSet};

// Re-exports from addressing
pub use addressing::{ContentAddress, compute_content_address};

// Re-exports from selective_disclosure
pub use selective_disclosure::{DisclosureProof, EncryptedSubtreeProof, RedactedMerkleProof};

// Re-exports from encryption
pub use encryption::{EncryptionDescriptor, EncryptionEnvelope, KeyAccess};

// Re-exports from resource_accounting
pub use resource_accounting::{ResourceError, VerificationCost as ResourceCost, VerificationLimit};
