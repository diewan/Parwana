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
