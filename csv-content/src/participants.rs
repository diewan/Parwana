//! Content participants
//!
//! Defines the roles and identities of participants in content creation,
//! modification, and verification.

use csv_hash::Hash;
use serde::{Deserialize, Serialize};
// L2 types containing L0 Hash fields cannot use serde
// Use manual serialization instead

/// A participant in a Sanad's content lifecycle.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    /// Unique identifier for this participant.
    pub id: ParticipantId,
    /// Role of this participant.
    pub role: ParticipantRole,
    /// Public key or address of this participant.
    pub public_key: Vec<u8>,
    /// When this participant was added.
    pub added_at: u64,
}

/// Unique identifier for a participant.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantId(pub Hash);

impl ParticipantId {
    /// Create a new participant ID.
    pub fn new(public_key: &[u8]) -> Self {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let hash = tagged_hash(HashDomain::Nullifier, public_key).hash;
        Self(hash)
    }

    /// Get the underlying hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }
}

/// Role of a participant in content.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantRole {
    /// The creator of the content.
    Creator,
    /// The current owner.
    Owner,
    /// Someone who can modify the content.
    Modifier,
    /// Someone who can verify the content.
    Verifier,
    /// Someone who can revoke the content.
    Revoker,
    /// A reader with no special privileges.
    Reader,
}

/// A participant set for a content tree.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParticipantSet {
    /// All participants.
    pub participants: Vec<Participant>,
    /// The primary creator.
    pub creator: Option<ParticipantId>,
    /// The current owner.
    pub owner: Option<ParticipantId>,
}

impl ParticipantSet {
    /// Add a participant.
    pub fn add(&mut self, participant: Participant) {
        match participant.role {
            ParticipantRole::Creator => self.creator = Some(participant.id.clone()),
            ParticipantRole::Owner => self.owner = Some(participant.id.clone()),
            _ => {}
        }
        self.participants.push(participant);
    }

    /// Get a participant by ID.
    pub fn get(&self, id: &ParticipantId) -> Option<&Participant> {
        self.participants.iter().find(|p| &p.id == id)
    }

    /// Check if a participant has a specific role.
    pub fn has_role(&self, participant_id: &ParticipantId, role: &ParticipantRole) -> bool {
        self.participants
            .iter()
            .any(|p| &p.id == participant_id && &p.role == role)
    }

    /// Get all participants with a specific role.
    pub fn by_role(&self, role: &ParticipantRole) -> Vec<&Participant> {
        self.participants
            .iter()
            .filter(|p| &p.role == role)
            .collect()
    }

    /// Get the creator.
    pub fn creator(&self) -> Option<&Participant> {
        self.creator.as_ref().and_then(|id| self.get(id))
    }

    /// Get the owner.
    pub fn owner(&self) -> Option<&Participant> {
        self.owner.as_ref().and_then(|id| self.get(id))
    }
}
