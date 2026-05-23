//! CSV Content - Content tree system
//!
//! Provides Merkleized content trees, selective disclosure proofs,
//! attachment references, and resource accounting for the CSV protocol.
//!
//! # Modules
//!
//! - `content_tree` - Merkleized content tree with selective disclosure
//! - `claims` - Content claims and rights management
//! - `attachments` - External attachment reference model
//! - `participants` - Content participant roles and identities
//! - `addressing` - Content addressing utilities
//! - `selective_disclosure` - Selective disclosure proofs
//! - `encryption` - Encryption envelopes for content
//! - `resource_accounting` - Verification resource limits

#![warn(missing_docs)]

pub mod content_tree;
pub mod claims;
pub mod attachments;
pub mod participants;
pub mod addressing;
pub mod selective_disclosure;
pub mod encryption;
pub mod resource_accounting;

// Re-exports from content_tree
pub use content_tree::{
    ContentTree, ContentNode, NodeType, NodeMetadata, AccessControl,
    ContentProof, DisclosureProof as ContentDisclosureProof, RedactedMerkleProof as ContentRedactedMerkleProof, EncryptedSubtreeProof as ContentEncryptedSubtreeProof,
    VerificationCost, VerificationCostError,
};

// Re-exports from claims
pub use claims::{Claim, ClaimPredicate, ContentRights, RightsTransfer};

// Re-exports from attachments
pub use attachments::{AttachmentRef, MediaType, AttachmentBudget};

// Re-exports from participants
pub use participants::{Participant, ParticipantId, ParticipantRole, ParticipantSet};

// Re-exports from addressing
pub use addressing::{ContentAddress, compute_content_address};

// Re-exports from selective_disclosure
pub use selective_disclosure::{DisclosureProof, RedactedMerkleProof, EncryptedSubtreeProof};

// Re-exports from encryption
pub use encryption::{EncryptionDescriptor, EncryptionEnvelope, KeyAccess};

// Re-exports from resource_accounting
pub use resource_accounting::{VerificationCost as ResourceCost, VerificationLimit, ResourceError};
