//! Content claims and rights
//!
//! Provides a system for expressing and verifying claims about content
//! and managing access rights to content nodes.

use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// A claim about content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The subject of the claim (who made it).
    pub subject: String,
    /// The object of the claim (what it's about).
    pub object: String,
    /// The predicate (type of claim).
    pub predicate: ClaimPredicate,
    /// When the claim was made.
    pub timestamp: u64,
    /// Whether the claim has been verified.
    pub verified: bool,
}

/// The type of claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimPredicate {
    /// The content is authentic.
    Authentic,
    /// The content is complete.
    Complete,
    /// The content is current (not outdated).
    Current,
    /// The content is authorized by the claimant.
    Authorized,
    /// The content meets a specific standard.
    Standard(String),
    /// Custom claim.
    Custom(String),
}

impl Claim {
    /// Create a new claim.
    pub fn new(
        subject: impl Into<String>,
        object: impl Into<String>,
        predicate: ClaimPredicate,
    ) -> Self {
        Self {
            subject: subject.into(),
            object: object.into(),
            predicate,
            timestamp: 0,
            verified: false,
        }
    }

    /// Hash this claim for storage.
    pub fn hash(&self) -> Hash {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let data = format!("{}:{}:{}", self.subject, self.object, self.predicate_tag());
        tagged_hash(HashDomain::VerificationProofV1, data.as_bytes()).hash
    }

    fn predicate_tag(&self) -> &str {
        match &self.predicate {
            ClaimPredicate::Authentic => "authentic",
            ClaimPredicate::Complete => "complete",
            ClaimPredicate::Current => "current",
            ClaimPredicate::Authorized => "authorized",
            ClaimPredicate::Standard(s) => s.as_str(),
            ClaimPredicate::Custom(s) => s.as_str(),
        }
    }
}

/// Rights management for content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentRights {
    /// Who owns this content.
    pub owner: String,
    /// Who can read this content.
    pub readers: Vec<String>,
    /// Who can modify this content.
    pub modifiers: Vec<String>,
    /// Who can revoke access.
    pub revokers: Vec<String>,
    /// Expiration time (0 = no expiration).
    pub expires_at: u64,
}

impl ContentRights {
    /// Check if a subject has read access.
    pub fn can_read(&self, subject: &str) -> bool {
        self.readers.is_empty() || self.readers.contains(&subject.to_string())
    }

    /// Check if a subject has write access.
    pub fn can_write(&self, subject: &str) -> bool {
        self.modifiers.is_empty() || self.modifiers.contains(&subject.to_string())
    }

    /// Check if a subject can revoke access.
    pub fn can_revoke(&self, subject: &str) -> bool {
        self.revokers.contains(&subject.to_string())
    }

    /// Check if the rights have expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at > 0
    }
}

/// A rights transfer request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RightsTransfer {
    /// The content being transferred.
    pub content_hash: Hash,
    /// From whom.
    pub from: String,
    /// To whom.
    pub to: String,
    /// New rights.
    pub new_rights: ContentRights,
    /// Authorization proof.
    pub authorization_proof: Vec<u8>,
}

impl RightsTransfer {
    /// Hash this transfer request.
    pub fn hash(&self) -> Hash {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let data = format!(
            "{}:{}:{}:{}",
            self.content_hash.to_hex(),
            self.from,
            self.to,
            self.new_rights.owner
        );
        tagged_hash(HashDomain::VerificationProofV1, data.as_bytes()).hash
    }
}
