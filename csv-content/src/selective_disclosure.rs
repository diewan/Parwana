//! Selective disclosure proof API.
//!
//! The canonical implementation lives in `content_tree`; this compatibility
//! module keeps one verification implementation for every public import path.

pub use crate::content_tree::{DisclosureProof, EncryptedSubtreeProof, RedactedMerkleProof};
