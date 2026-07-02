//! Attachment reference model
//!
//! Provides a system for referencing external content attachments
//! without storing large blobs directly in Sanads.

use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// A reference to an external attachment.
/// L2 type: uses manual serialization for Hash field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRef {
    /// Content identifier (CID or similar).
    pub cid: String,
    /// MIME type of the attachment.
    pub media_type: MediaType,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 hash of the attachment content.
    pub hash: Hash,
    /// Optional encryption key ID.
    pub encryption_key_id: Option<String>,
    /// When the attachment was created.
    pub created_at: u64,
}

impl AttachmentRef {
    /// Create a new attachment reference.
    pub fn new(cid: impl Into<String>, media_type: MediaType, size: u64, hash: Hash) -> Self {
        Self {
            cid: cid.into(),
            media_type,
            size,
            hash,
            encryption_key_id: None,
            created_at: 0,
        }
    }

    /// Set the encryption key ID.
    pub fn with_encryption_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.encryption_key_id = Some(key_id.into());
        self
    }

    /// Set the creation timestamp.
    pub fn with_created_at(mut self, timestamp: u64) -> Self {
        self.created_at = timestamp;
        self
    }
}

impl serde::Serialize for AttachmentRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AttachmentRef", 6)?;
        s.serialize_field("cid", &self.cid)?;
        s.serialize_field("media_type", &self.media_type)?;
        s.serialize_field("size", &self.size)?;
        s.serialize_field("hash", &self.hash.0)?;
        s.serialize_field("encryption_key_id", &self.encryption_key_id)?;
        s.serialize_field("created_at", &self.created_at)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for AttachmentRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Cid,
            MediaType,
            Size,
            Hash,
            EncryptionKeyId,
            CreatedAt,
        }

        struct AttachmentRefVisitor;

        impl<'de> serde::de::Visitor<'de> for AttachmentRefVisitor {
            type Value = AttachmentRef;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct AttachmentRef")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let cid = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let media_type = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let size = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let encryption_key_id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                let created_at = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                Ok(AttachmentRef {
                    cid,
                    media_type,
                    size,
                    hash: Hash(hash_bytes),
                    encryption_key_id,
                    created_at,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut cid = None;
                let mut media_type = None;
                let mut size = None;
                let mut hash = None;
                let mut encryption_key_id = None;
                let mut created_at = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Cid => {
                            if cid.is_some() {
                                return Err(serde::de::Error::duplicate_field("cid"));
                            }
                            cid = Some(map.next_value()?);
                        }
                        Field::MediaType => {
                            if media_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("media_type"));
                            }
                            media_type = Some(map.next_value()?);
                        }
                        Field::Size => {
                            if size.is_some() {
                                return Err(serde::de::Error::duplicate_field("size"));
                            }
                            size = Some(map.next_value()?);
                        }
                        Field::Hash => {
                            if hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            hash = Some(Hash(hash_bytes));
                        }
                        Field::EncryptionKeyId => {
                            if encryption_key_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("encryption_key_id"));
                            }
                            encryption_key_id = Some(map.next_value()?);
                        }
                        Field::CreatedAt => {
                            if created_at.is_some() {
                                return Err(serde::de::Error::duplicate_field("created_at"));
                            }
                            created_at = Some(map.next_value()?);
                        }
                    }
                }

                let cid = cid.ok_or_else(|| serde::de::Error::missing_field("cid"))?;
                let media_type =
                    media_type.ok_or_else(|| serde::de::Error::missing_field("media_type"))?;
                let size = size.ok_or_else(|| serde::de::Error::missing_field("size"))?;
                let hash = hash.ok_or_else(|| serde::de::Error::missing_field("hash"))?;
                let created_at =
                    created_at.ok_or_else(|| serde::de::Error::missing_field("created_at"))?;

                Ok(AttachmentRef {
                    cid,
                    media_type,
                    size,
                    hash,
                    encryption_key_id,
                    created_at,
                })
            }
        }

        deserializer.deserialize_struct(
            "AttachmentRef",
            &[
                "cid",
                "media_type",
                "size",
                "hash",
                "encryption_key_id",
                "created_at",
            ],
            AttachmentRefVisitor,
        )
    }
}

/// MIME media type for attachments.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    /// Plain text.
    Text,
    /// JSON.
    Json,
    /// XML.
    Xml,
    /// PDF.
    Pdf,
    /// Image (generic).
    Image,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// MP4 video.
    Mp4,
    /// MP3 audio.
    Mp3,
    /// ZIP archive.
    Zip,
    /// Custom type.
    Custom(String),
}

impl MediaType {
    /// Get the string representation of this media type.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::Pdf => "application/pdf",
            Self::Image => "image/*",
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Mp4 => "video/mp4",
            Self::Mp3 => "audio/mpeg",
            Self::Zip => "application/zip",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Budget for attachments on a Sanad.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentBudget {
    /// Maximum number of attachments.
    pub max_count: u32,
    /// Maximum total size in bytes.
    pub max_total_size: u64,
    /// Maximum size for a single attachment.
    pub max_single_size: u64,
    /// Allowed media types.
    pub allowed_types: Vec<MediaType>,
}

impl Default for AttachmentBudget {
    fn default() -> Self {
        Self {
            max_count: 10,
            max_total_size: 100 * 1024 * 1024, // 100 MB
            max_single_size: 50 * 1024 * 1024, // 50 MB
            allowed_types: vec![
                MediaType::Json,
                MediaType::Pdf,
                MediaType::Png,
                MediaType::Jpeg,
                MediaType::Custom("application/octet-stream".to_string()),
            ],
        }
    }
}

impl AttachmentBudget {
    /// Check if an attachment reference is within budget.
    pub fn is_within_budget(&self, attachment: &AttachmentRef) -> bool {
        if attachment.size > self.max_single_size {
            return false;
        }
        if !self.allowed_types.contains(&attachment.media_type) {
            return false;
        }
        true
    }

    /// Check if adding an attachment would exceed the budget.
    pub fn would_exceed_budget(
        &self,
        current_count: u32,
        current_size: u64,
        attachment: &AttachmentRef,
    ) -> bool {
        if current_count >= self.max_count {
            return true;
        }
        if current_size + attachment.size > self.max_total_size {
            return true;
        }
        false
    }
}
