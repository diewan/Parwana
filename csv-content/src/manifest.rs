//! Off-chain Sanad manifest.
//!
//! A [`SanadManifest`] is a small, canonical, hash-verifiable description of
//! what a Sanad represents — title/description, schema, payload codec/hash,
//! content root, and per-attachment metadata (name/CID, media type, size, hash,
//! encryption status). It carries **no** payload or attachment blobs; those
//! stay off-chain and are fetched separately.
//!
//! The manifest is off-chain state only. On-chain state continues to carry just
//! commitments/seal state; the protocol descriptor carries the canonical hashes
//! and roots. The manifest's job is to let a holder *see and verify* what a
//! Sanad binds: its derived `payload_hash` / `content_root` / `attachment_root`
//! can be checked against the Sanad descriptor before any metadata is presented
//! as authoritative (`SANAD-MANIFEST-001`).
//!
//! ## Canonical encoding
//!
//! Hashing uses a manual, length-prefixed byte encoding
//! ([`SanadManifest::to_canonical_bytes`]) — never `serde_json`. JSON may be
//! used purely as a CLI authoring format, but it must be converted into this
//! canonical form before hashing or binding.

use crate::attachments::MediaType;
use csv_hash::{Hash, tagged_hash_str};

/// Domain tag for the stable manifest hash.
pub const DOMAIN_SANAD_MANIFEST_V1: &str = "urn:lnp-bp:csv:csv.sanad.manifest.v1";

/// Current manifest schema version.
pub const SANAD_MANIFEST_VERSION: u16 = 1;

/// Errors produced while building or validating a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The declared `attachment_root` does not match the root recomputed from
    /// the attachment hashes.
    AttachmentRootMismatch {
        /// Root declared in the manifest.
        declared: Option<Hash>,
        /// Root recomputed from the attachments.
        computed: Option<Hash>,
    },
    /// The manifest's hashes/roots do not match the Sanad descriptor.
    DescriptorMismatch {
        /// Human-readable description of which field diverged.
        field: &'static str,
    },
    /// Canonical decode failed.
    Decode(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::AttachmentRootMismatch { declared, computed } => write!(
                f,
                "attachment root mismatch: declared {:?}, computed {:?}",
                declared.as_ref().map(|h| h.as_bytes()),
                computed.as_ref().map(|h| h.as_bytes()),
            ),
            ManifestError::DescriptorMismatch { field } => {
                write!(f, "manifest does not match Sanad descriptor field: {field}")
            }
            ManifestError::Decode(msg) => write!(f, "manifest decode error: {msg}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// A single attachment's display + verification metadata (no blob bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanadManifestAttachment {
    /// Human-readable name, if any.
    pub name: Option<String>,
    /// Content identifier (CID / URL), if any.
    pub cid: Option<String>,
    /// MIME media type.
    pub media_type: MediaType,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 hash of the attachment content.
    pub hash: Hash,
    /// Whether the attachment content is encrypted.
    pub encrypted: bool,
    /// Encryption key identifier, if encrypted.
    pub encryption_key_id: Option<String>,
}

/// Canonical off-chain description of a Sanad's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanadManifest {
    /// Manifest schema version.
    pub version: u16,
    /// Optional short title.
    pub title: Option<String>,
    /// Optional longer description.
    pub description: Option<String>,
    /// Schema / type label.
    pub schema: String,
    /// Payload codec label (e.g. "cbor", "json", "octet-stream").
    pub payload_codec: String,
    /// Hash of the payload content.
    pub payload_hash: Hash,
    /// Optional Merkle root over content subtrees.
    pub content_root: Option<Hash>,
    /// Per-attachment metadata.
    pub attachments: Vec<SanadManifestAttachment>,
    /// Optional root over attachment hashes.
    pub attachment_root: Option<Hash>,
    /// Optional disclosure policy hash.
    pub disclosure_policy_hash: Option<Hash>,
    /// Optional proof policy hash.
    pub proof_policy_hash: Option<Hash>,
}

// ── manual canonical encoding helpers ────────────────────────────────────────

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_opt_str(out: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(v) => {
            out.push(1);
            put_str(out, v);
        }
        None => out.push(0),
    }
}

fn put_opt_hash(out: &mut Vec<u8>, h: &Option<Hash>) {
    match h {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(v.as_bytes());
        }
        None => out.push(0),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ManifestError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ManifestError::Decode("length overflow".into()))?;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or_else(|| ManifestError::Decode("unexpected end of input".into()))?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ManifestError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ManifestError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String, ManifestError> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| ManifestError::Decode(e.to_string()))
    }
    fn opt_string(&mut self) -> Result<Option<String>, ManifestError> {
        if self.u8()? == 1 {
            Ok(Some(self.string()?))
        } else {
            Ok(None)
        }
    }
    fn hash(&mut self) -> Result<Hash, ManifestError> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.take(32)?);
        Ok(Hash::new(arr))
    }
    fn opt_hash(&mut self) -> Result<Option<Hash>, ManifestError> {
        if self.u8()? == 1 {
            Ok(Some(self.hash()?))
        } else {
            Ok(None)
        }
    }
    fn finish(self) -> Result<(), ManifestError> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(ManifestError::Decode("trailing bytes".into()))
        }
    }
}

fn media_type_from_str(s: &str) -> MediaType {
    match s {
        "text/plain" => MediaType::Text,
        "application/json" => MediaType::Json,
        "application/xml" => MediaType::Xml,
        "application/pdf" => MediaType::Pdf,
        "image/*" => MediaType::Image,
        "image/png" => MediaType::Png,
        "image/jpeg" => MediaType::Jpeg,
        "image/gif" => MediaType::Gif,
        "video/mp4" => MediaType::Mp4,
        "audio/mpeg" => MediaType::Mp3,
        "application/zip" => MediaType::Zip,
        other => MediaType::Custom(other.to_string()),
    }
}

impl SanadManifest {
    /// Compute the Merkle root over the declared attachment hashes.
    ///
    /// Uses the same construction as Sanad creation (a [`crate::ContentTree`]
    /// over each attachment's 32-byte hash), so the derived root can be matched
    /// against the Sanad descriptor's `attachment_root`. Returns `None` when
    /// there are no attachments.
    pub fn compute_attachment_root(&self) -> Option<Hash> {
        if self.attachments.is_empty() {
            return None;
        }
        let leaves: Vec<Vec<u8>> = self
            .attachments
            .iter()
            .map(|a| a.hash.as_bytes().to_vec())
            .collect();
        Some(crate::ContentTree::from_leaves(leaves).root_hash)
    }

    /// Verify the declared `attachment_root` matches the recomputed root.
    pub fn validate_attachment_root(&self) -> Result<(), ManifestError> {
        let computed = self.compute_attachment_root();
        if self.attachment_root == computed {
            Ok(())
        } else {
            Err(ManifestError::AttachmentRootMismatch {
                declared: self.attachment_root,
                computed,
            })
        }
    }

    /// Check the manifest's hashes/roots against a Sanad descriptor's hashes.
    ///
    /// The manifest must not silently diverge from the descriptor it claims to
    /// describe: `payload_hash`, `content_root`, and `attachment_root` must all
    /// match. Fails closed with a [`ManifestError::DescriptorMismatch`] naming
    /// the first divergent field.
    pub fn matches_descriptor_roots(
        &self,
        payload_hash: &Hash,
        content_root: &Option<Hash>,
        attachment_root: &Option<Hash>,
    ) -> Result<(), ManifestError> {
        if &self.payload_hash != payload_hash {
            return Err(ManifestError::DescriptorMismatch {
                field: "payload_hash",
            });
        }
        if &self.content_root != content_root {
            return Err(ManifestError::DescriptorMismatch {
                field: "content_root",
            });
        }
        if &self.attachment_root != attachment_root {
            return Err(ManifestError::DescriptorMismatch {
                field: "attachment_root",
            });
        }
        Ok(())
    }

    /// Serialize to canonical, length-prefixed bytes (deterministic; no serde).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        put_opt_str(&mut out, &self.title);
        put_opt_str(&mut out, &self.description);
        put_str(&mut out, &self.schema);
        put_str(&mut out, &self.payload_codec);
        out.extend_from_slice(self.payload_hash.as_bytes());
        put_opt_hash(&mut out, &self.content_root);
        out.extend_from_slice(&(self.attachments.len() as u32).to_le_bytes());
        for a in &self.attachments {
            put_opt_str(&mut out, &a.name);
            put_opt_str(&mut out, &a.cid);
            put_str(&mut out, a.media_type.as_str());
            out.extend_from_slice(&a.size.to_le_bytes());
            out.extend_from_slice(a.hash.as_bytes());
            out.push(a.encrypted as u8);
            put_opt_str(&mut out, &a.encryption_key_id);
        }
        put_opt_hash(&mut out, &self.attachment_root);
        put_opt_hash(&mut out, &self.disclosure_policy_hash);
        put_opt_hash(&mut out, &self.proof_policy_hash);
        out
    }

    /// Decode from canonical bytes produced by [`Self::to_canonical_bytes`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        let title = r.opt_string()?;
        let description = r.opt_string()?;
        let schema = r.string()?;
        let payload_codec = r.string()?;
        let payload_hash = r.hash()?;
        let content_root = r.opt_hash()?;
        let count = r.u32()? as usize;
        let mut attachments = Vec::with_capacity(count);
        for _ in 0..count {
            let name = r.opt_string()?;
            let cid = r.opt_string()?;
            let media_type = media_type_from_str(&r.string()?);
            let size = r.u64()?;
            let hash = r.hash()?;
            let encrypted = r.u8()? != 0;
            let encryption_key_id = r.opt_string()?;
            attachments.push(SanadManifestAttachment {
                name,
                cid,
                media_type,
                size,
                hash,
                encrypted,
                encryption_key_id,
            });
        }
        let attachment_root = r.opt_hash()?;
        let disclosure_policy_hash = r.opt_hash()?;
        let proof_policy_hash = r.opt_hash()?;
        r.finish()?;
        Ok(Self {
            version,
            title,
            description,
            schema,
            payload_codec,
            payload_hash,
            content_root,
            attachments,
            attachment_root,
            disclosure_policy_hash,
            proof_policy_hash,
        })
    }

    /// Stable, domain-separated hash of the canonical manifest bytes.
    pub fn manifest_hash(&self) -> Hash {
        Hash::new(tagged_hash_str(
            DOMAIN_SANAD_MANIFEST_V1,
            &self.to_canonical_bytes(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(byte: u8, size: u64) -> SanadManifestAttachment {
        SanadManifestAttachment {
            name: Some(format!("file-{byte}")),
            cid: None,
            media_type: MediaType::Png,
            size,
            hash: Hash::new([byte; 32]),
            encrypted: false,
            encryption_key_id: None,
        }
    }

    fn sample() -> SanadManifest {
        let attachments = vec![attachment(1, 100), attachment(2, 200)];
        let mut m = SanadManifest {
            version: SANAD_MANIFEST_VERSION,
            title: Some("Invoice #7".into()),
            description: None,
            schema: "csv.invoice.v1".into(),
            payload_codec: "cbor".into(),
            payload_hash: Hash::new([9u8; 32]),
            content_root: Some(Hash::new([8u8; 32])),
            attachments,
            attachment_root: None,
            disclosure_policy_hash: None,
            proof_policy_hash: None,
        };
        m.attachment_root = m.compute_attachment_root();
        m
    }

    #[test]
    fn roundtrip_is_stable() {
        let m = sample();
        let bytes = m.to_canonical_bytes();
        let decoded = SanadManifest::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
        assert_eq!(m.manifest_hash(), decoded.manifest_hash());
    }

    #[test]
    fn hash_changes_with_content() {
        let m = sample();
        let mut m2 = m.clone();
        m2.title = Some("Invoice #8".into());
        assert_ne!(m.manifest_hash(), m2.manifest_hash());
    }

    #[test]
    fn attachment_root_validates() {
        let m = sample();
        assert!(m.validate_attachment_root().is_ok());
    }

    #[test]
    fn tampered_attachment_hash_is_detected() {
        // A manifest whose declared attachment_root no longer matches its
        // attachments (e.g. an attachment hash was swapped) must fail closed.
        let mut m = sample();
        m.attachments[0].hash = Hash::new([0xFFu8; 32]);
        assert!(matches!(
            m.validate_attachment_root(),
            Err(ManifestError::AttachmentRootMismatch { .. })
        ));
    }

    #[test]
    fn matches_descriptor_roots_ok_and_mismatch() {
        let m = sample();
        assert!(
            m.matches_descriptor_roots(&m.payload_hash, &m.content_root, &m.attachment_root)
                .is_ok()
        );
        let wrong = Hash::new([0x11u8; 32]);
        assert!(matches!(
            m.matches_descriptor_roots(&wrong, &m.content_root, &m.attachment_root),
            Err(ManifestError::DescriptorMismatch {
                field: "payload_hash"
            })
        ));
    }

    #[test]
    fn empty_attachments_has_no_root() {
        let mut m = sample();
        m.attachments.clear();
        assert_eq!(m.compute_attachment_root(), None);
    }

    #[test]
    fn decode_rejects_truncated() {
        let m = sample();
        let bytes = m.to_canonical_bytes();
        assert!(SanadManifest::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
