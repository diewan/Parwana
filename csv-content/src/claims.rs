//! Content claims and rights
//!
//! Provides a system for expressing and verifying claims about content
//! and managing access rights to content nodes.

use csv_hash::Hash;
use serde::{Deserialize, Serialize};
// L2 types containing L0 Hash fields cannot use serde
// Use manual serialization instead

/// A claim about content.
/// L2 type without Hash fields - can use serde
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
/// L2 type without Hash fields - can use serde
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
/// L2 type without Hash fields - can use serde
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
/// L2 type: uses manual serialization for Hash field
#[derive(Debug, Clone)]
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

impl serde::Serialize for RightsTransfer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("RightsTransfer", 5)?;
        s.serialize_field("content_hash", &self.content_hash.0)?;
        s.serialize_field("from", &self.from)?;
        s.serialize_field("to", &self.to)?;
        s.serialize_field("new_rights", &self.new_rights)?;
        s.serialize_field("authorization_proof", &self.authorization_proof)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for RightsTransfer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            ContentHash,
            From,
            To,
            NewRights,
            AuthorizationProof,
        }

        struct RightsTransferVisitor;

        impl<'de> serde::de::Visitor<'de> for RightsTransferVisitor {
            type Value = RightsTransfer;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct RightsTransfer")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let content_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let from = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let to = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let new_rights = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let authorization_proof = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                Ok(RightsTransfer {
                    content_hash: Hash(content_hash_bytes),
                    from,
                    to,
                    new_rights,
                    authorization_proof,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut content_hash = None;
                let mut from = None;
                let mut to = None;
                let mut new_rights = None;
                let mut authorization_proof = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ContentHash => {
                            if content_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("content_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            content_hash = Some(Hash(hash_bytes));
                        }
                        Field::From => {
                            if from.is_some() {
                                return Err(serde::de::Error::duplicate_field("from"));
                            }
                            from = Some(map.next_value()?);
                        }
                        Field::To => {
                            if to.is_some() {
                                return Err(serde::de::Error::duplicate_field("to"));
                            }
                            to = Some(map.next_value()?);
                        }
                        Field::NewRights => {
                            if new_rights.is_some() {
                                return Err(serde::de::Error::duplicate_field("new_rights"));
                            }
                            new_rights = Some(map.next_value()?);
                        }
                        Field::AuthorizationProof => {
                            if authorization_proof.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "authorization_proof",
                                ));
                            }
                            authorization_proof = Some(map.next_value()?);
                        }
                    }
                }

                let content_hash =
                    content_hash.ok_or_else(|| serde::de::Error::missing_field("content_hash"))?;
                let from = from.ok_or_else(|| serde::de::Error::missing_field("from"))?;
                let to = to.ok_or_else(|| serde::de::Error::missing_field("to"))?;
                let new_rights =
                    new_rights.ok_or_else(|| serde::de::Error::missing_field("new_rights"))?;
                let authorization_proof = authorization_proof
                    .ok_or_else(|| serde::de::Error::missing_field("authorization_proof"))?;

                Ok(RightsTransfer {
                    content_hash,
                    from,
                    to,
                    new_rights,
                    authorization_proof,
                })
            }
        }

        deserializer.deserialize_struct(
            "RightsTransfer",
            &[
                "content_hash",
                "from",
                "to",
                "new_rights",
                "authorization_proof",
            ],
            RightsTransferVisitor,
        )
    }
}
