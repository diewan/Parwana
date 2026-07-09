//! Sanad types with payload descriptor support
//!
//! A Sanad is a verifiable, single-use digital asset that binds:
//! - A content descriptor (schema, payload hash, content root, etc.)
//! - A commitment hash
//! - An owner proof
//! - A salt for uniqueness
//!
//! The Sanad ID is derived via domain-separated tagged hashing:
//! ```text
//! SanadId = tagged_hash("csv.sanad.id.v1", descriptor_hash || commitment || salt)
//! ```
//!
//! This ensures the descriptor is cryptographically bound to the Sanad identity,
//! preventing two implementations from creating different Sanads for the same content.

pub use csv_hash::sanad::SanadId;

use csv_codec::CodecError;
use csv_codec::manual_encoder::{CanonicalEncoding, EncodingFormat, ManualEncoder};

use crate::error::{ProtocolError, Result};
use crate::signature::SignatureScheme;
use crate::wire::{HashWire, SanadIdWire};
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_hash::{Commitment, Hash};

/// Decode a wire hash field into its canonical 32 bytes, failing closed.
///
/// Canonical MCE encoding is fixed-width: a hash field that decoded to anything
/// other than 32 bytes would silently shift every subsequent field, so a short
/// or malformed value must abort the encode rather than be padded. The previous
/// code substituted `vec![0u8; 32]` on decode failure, which both hid the error
/// and fed an all-zero value into the hashed preimage
/// (`DECODE-ZEROFILL-FAILCLOSED-001`).
fn hash_field(wire: &HashWire, field: &str) -> csv_codec::CodecResult<[u8; 32]> {
    wire.to_hash().map(|hash| *hash.as_bytes()).map_err(|e| {
        CodecError::SerializationError(format!("Invalid `{}` hash field: {}", field, e))
    })
}

/// Same as [`hash_field`] for an optional field: `None` stays `None`, but a
/// present-but-malformed value fails closed rather than encoding as zeros.
fn optional_hash_field(
    wire: Option<&HashWire>,
    field: &str,
) -> csv_codec::CodecResult<Option<Vec<u8>>> {
    wire.map(|w| hash_field(w, field).map(|bytes| bytes.to_vec()))
        .transpose()
}

/// [`hash_field`] for the `SanadIdWire`-typed id, which has its own decoder.
fn sanad_id_field(wire: &SanadIdWire, field: &str) -> csv_codec::CodecResult<[u8; 32]> {
    wire.to_sanad_id().map(|id| *id.as_bytes()).map_err(|e| {
        CodecError::SerializationError(format!("Invalid `{}` sanad id field: {}", field, e))
    })
}

/// Canonical payload descriptor for a Sanad.
///
/// This descriptor binds all content metadata to the Sanad identity.
/// The descriptor is serialized to canonical CBOR and hashed; the hash
/// is included in SanadId derivation.
///
/// ## Design Rationale
///
/// The descriptor is NOT stored on-chain. Only its hash is committed.
/// This keeps on-chain storage minimal while ensuring off-chain
/// implementations can verify content binding via the descriptor hash.
///
/// ## Fields
///
/// - `schema_id`: Registered schema identifier for payload structure
/// - `schema_hash`: Hash of the schema definition (for versioning)
/// - `payload_codec`: Canonical serialization codec (CBOR, etc.)
/// - `payload_hash`: Hash of the actual payload content
/// - `content_root`: Optional Merkle root over content subtrees
/// - `attachment_root`: Optional root over attachment hashes
/// - `claims_root`: Optional root over claim hashes
/// - `participants_root`: Optional root over participant hashes
/// - `disclosure_policy_hash`: Hash of the disclosure policy
/// - `proof_policy_hash`: Hash of the proof policy
/// - `resource_limits_hash`: Hash of resource limits (max size, depth, etc.)
///
/// **Layer:** L1
/// **Serde:** FORBIDDEN - uses manual CanonicalEncoding via csv-codec
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanadPayloadDescriptor {
    /// Schema identifier (e.g., "csv.sanad.content.v1")
    pub schema_id: String,
    /// Hash of the schema definition for versioning
    pub schema_hash: HashWire,
    /// Canonical serialization codec identifier
    pub payload_codec: u8,
    /// Hash of the payload content
    pub payload_hash: HashWire,
    /// Optional Merkle root over content subtrees
    pub content_root: Option<HashWire>,
    /// Optional root over attachment hashes
    pub attachment_root: Option<HashWire>,
    /// Optional root over claim hashes
    pub claims_root: Option<HashWire>,
    /// Optional root over participant hashes
    pub participants_root: Option<HashWire>,
    /// Hash of the disclosure policy
    pub disclosure_policy_hash: HashWire,
    /// Hash of the proof policy
    pub proof_policy_hash: HashWire,
    /// Hash of resource limits
    pub resource_limits_hash: HashWire,
}

impl SanadPayloadDescriptor {
    /// Canonical schema ID for version 1 descriptors.
    pub const SCHEMA_ID: &'static str = "csv.sanad.descriptor.v1";

    /// Create a new descriptor with default resource limits.
    pub fn new(
        schema_id: impl Into<String>,
        schema_hash: Hash,
        payload_codec: u8,
        payload_hash: Hash,
        content_root: Option<Hash>,
        disclosure_policy_hash: Hash,
        proof_policy_hash: Hash,
    ) -> Self {
        Self {
            schema_id: schema_id.into(),
            schema_hash: schema_hash.into(),
            payload_codec,
            payload_hash: payload_hash.into(),
            content_root: content_root.map(|h| h.into()),
            attachment_root: None,
            claims_root: None,
            participants_root: None,
            disclosure_policy_hash: disclosure_policy_hash.into(),
            proof_policy_hash: proof_policy_hash.into(),
            resource_limits_hash: Hash::new([0u8; 32]).into(), // Default: no resource limits
        }
    }

    /// Compute the canonical descriptor hash (manually encoded, then hashed).
    ///
    /// This hash is what gets bound into the SanadId derivation.
    pub fn compute_hash(&self) -> Hash {
        match self.encode_mce() {
            Ok(bytes) => Hash::sha256(&bytes),
            Err(_) => {
                // Fallback: if canonical serialization fails, use a zero hash.
                // In production, this should never happen for well-formed descriptors.
                Hash::new([0u8; 32])
            }
        }
    }

    /// Set the attachment root.
    pub fn with_attachment_root(mut self, root: Hash) -> Self {
        self.attachment_root = Some(root.into());
        self
    }

    /// Set the claims root.
    pub fn with_claims_root(mut self, root: Hash) -> Self {
        self.claims_root = Some(root.into());
        self
    }

    /// Set the participants root.
    pub fn with_participants_root(mut self, root: Hash) -> Self {
        self.participants_root = Some(root.into());
        self
    }

    /// Set the resource limits hash.
    pub fn with_resource_limits(mut self, hash: Hash) -> Self {
        self.resource_limits_hash = hash.into();
        self
    }
}

impl CanonicalEncoding for SanadPayloadDescriptor {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => {
                // MCE: fixed-width byte concatenation
                let mut result = Vec::new();

                // schema_id: length-prefixed string
                let schema_id_bytes = self.schema_id.as_bytes();
                result
                    .extend_from_slice(&ManualEncoder::encode_u32_le(schema_id_bytes.len() as u32));
                result.extend_from_slice(schema_id_bytes);

                // schema_hash: 32 bytes
                result.extend_from_slice(&hash_field(&self.schema_hash, "schema_hash")?);

                // payload_codec: 1 byte
                result.push(self.payload_codec);

                // payload_hash: 32 bytes
                result.extend_from_slice(&hash_field(&self.payload_hash, "payload_hash")?);

                // content_root: optional 32 bytes (1 byte flag + 32 bytes if present)
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.content_root.as_ref(), "content_root")?,
                ));

                // attachment_root: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.attachment_root.as_ref(), "attachment_root")?,
                ));

                // claims_root: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.claims_root.as_ref(), "claims_root")?,
                ));

                // participants_root: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.participants_root.as_ref(), "participants_root")?,
                ));

                // disclosure_policy_hash: 32 bytes
                result.extend_from_slice(&hash_field(
                    &self.disclosure_policy_hash,
                    "disclosure_policy_hash",
                )?);

                // proof_policy_hash: 32 bytes
                result
                    .extend_from_slice(&hash_field(&self.proof_policy_hash, "proof_policy_hash")?);

                // resource_limits_hash: 32 bytes
                result.extend_from_slice(&hash_field(
                    &self.resource_limits_hash,
                    "resource_limits_hash",
                )?);

                Ok(result)
            }
            EncodingFormat::ManualBinary => {
                // Manual binary: same as MCE for now
                self.encode(EncodingFormat::MCE)
            }
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        let mut pos = 0;

        // schema_id: length-prefixed string
        let schema_id_len = ManualEncoder::decode_u32_le(bytes, &mut pos)?;
        if bytes.len() < pos + schema_id_len as usize {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for schema_id".to_string(),
            ));
        }
        let schema_id = String::from_utf8(bytes[pos..pos + schema_id_len as usize].to_vec())
            .map_err(|e| {
                CodecError::DeserializationError(format!("Invalid UTF-8 for schema_id: {}", e))
            })?;
        pos += schema_id_len as usize;

        // schema_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for schema_hash".to_string(),
            ));
        }
        let mut schema_hash_arr = [0u8; 32];
        schema_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let schema_hash = HashWire {
            bytes: hex::encode(schema_hash_arr),
        };
        pos += 32;

        // payload_codec: 1 byte
        if bytes.len() < pos + 1 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for payload_codec".to_string(),
            ));
        }
        let payload_codec = bytes[pos];
        pos += 1;

        // payload_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for payload_hash".to_string(),
            ));
        }
        let mut payload_hash_arr = [0u8; 32];
        payload_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let payload_hash = HashWire {
            bytes: hex::encode(payload_hash_arr),
        };
        pos += 32;

        // content_root: optional 32 bytes
        let content_root = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // attachment_root: optional 32 bytes
        let attachment_root = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // claims_root: optional 32 bytes
        let claims_root = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // participants_root: optional 32 bytes
        let participants_root = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // disclosure_policy_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for disclosure_policy_hash".to_string(),
            ));
        }
        let mut disclosure_policy_hash_arr = [0u8; 32];
        disclosure_policy_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let disclosure_policy_hash = HashWire {
            bytes: hex::encode(disclosure_policy_hash_arr),
        };
        pos += 32;

        // proof_policy_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for proof_policy_hash".to_string(),
            ));
        }
        let mut proof_policy_hash_arr = [0u8; 32];
        proof_policy_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let proof_policy_hash = HashWire {
            bytes: hex::encode(proof_policy_hash_arr),
        };
        pos += 32;

        // resource_limits_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for resource_limits_hash".to_string(),
            ));
        }
        let mut resource_limits_hash_arr = [0u8; 32];
        resource_limits_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let resource_limits_hash = HashWire {
            bytes: hex::encode(resource_limits_hash_arr),
        };

        Ok(Self {
            schema_id,
            schema_hash,
            payload_codec,
            payload_hash,
            content_root,
            attachment_root,
            claims_root,
            participants_root,
            disclosure_policy_hash,
            proof_policy_hash,
            resource_limits_hash,
        })
    }
}

/// Domain tag for the canonical message signed by an [`OwnershipProof`].
///
/// The owner signs a domain-separated digest over the Sanad's descriptor hash,
/// commitment, salt, and owner identity, so the ownership signature is bound to
/// the exact Sanad it claims to own and cannot be replayed onto a different
/// content/state/owner (`SANAD-OWNERSHIP-PROOF-VERIFY-001`).
pub const DOMAIN_OWNERSHIP_PROOF_V1: &str = "urn:lnp-bp:csv:csv.sanad.ownership.v1";

/// Ownership proof binding a Sanad to an owner.
///
/// The proof carries the signer's `public_key` (needed to verify `proof`) and
/// the human-readable `owner` address. Verification checks that `proof` is a
/// valid signature by `public_key` over the canonical ownership message and
/// that `public_key` actually derives to `owner` for the target chain — so a
/// proof cannot claim ownership under an address whose key it does not hold.
///
/// **Layer:** L1
/// **Serde:** FORBIDDEN - uses manual CanonicalEncoding via csv-codec
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipProof {
    /// Proof bytes (a signature by `public_key` over the canonical message)
    pub proof: Vec<u8>,
    /// Owner identifier (chain address bytes)
    pub owner: Vec<u8>,
    /// Optional signature scheme hint
    pub scheme: Option<SignatureScheme>,
    /// Public key of the signer (the counterpart to `owner`). Required for a
    /// verifiable proof; empty only for legacy/unsigned drafts that must fail
    /// closed before being treated as authoritative.
    pub public_key: Vec<u8>,
}

impl OwnershipProof {
    /// Compute the canonical 32-byte message the owner signs / a verifier checks.
    ///
    /// `message = tagged_hash(DOMAIN_OWNERSHIP_PROOF_V1,
    ///                        descriptor_hash || commitment || salt || owner)`.
    ///
    /// This is the single source of truth shared by the signer (CLI publish
    /// path) and the verifier so the two never diverge.
    pub fn signing_message(
        descriptor_hash: &Hash,
        commitment: &Hash,
        salt: &[u8],
        owner: &[u8],
    ) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(64 + salt.len() + owner.len());
        preimage.extend_from_slice(descriptor_hash.as_bytes());
        preimage.extend_from_slice(commitment.as_bytes());
        preimage.extend_from_slice(salt);
        preimage.extend_from_slice(owner);
        csv_hash::tagged_hash_str(DOMAIN_OWNERSHIP_PROOF_V1, &preimage)
    }

    /// Cryptographically verify this ownership proof against the Sanad it binds.
    ///
    /// Fails closed unless **all** of the following hold:
    /// - a signature scheme is declared,
    /// - `proof`, `public_key`, and `owner` are all non-empty,
    /// - `proof` is a valid signature by `public_key` over
    ///   [`OwnershipProof::signing_message`], and
    /// - `public_key` derives to the `owner` address for `chain`.
    ///
    /// The last check binds the signer's key to the claimed owner, closing the
    /// self-certifying gap where any valid (key, signature) pair would
    /// otherwise "prove" ownership of an unrelated address.
    pub fn verify(
        &self,
        chain: &csv_hash::ChainId,
        descriptor_hash: &Hash,
        commitment: &Hash,
        salt: &[u8],
    ) -> Result<()> {
        let scheme = self.scheme.ok_or_else(|| {
            ProtocolError::SignatureVerificationFailed(
                "Ownership proof has no signature scheme".to_string(),
            )
        })?;
        if self.proof.is_empty() {
            return Err(ProtocolError::SignatureVerificationFailed(
                "Ownership proof signature bytes are empty".to_string(),
            ));
        }
        if self.public_key.is_empty() {
            return Err(ProtocolError::SignatureVerificationFailed(
                "Ownership proof public key is empty".to_string(),
            ));
        }
        if self.owner.is_empty() {
            return Err(ProtocolError::SignatureVerificationFailed(
                "Ownership proof owner is empty".to_string(),
            ));
        }

        // 1. Signature validity over the canonical message.
        let message = Self::signing_message(descriptor_hash, commitment, salt, &self.owner);
        let signature = crate::signature::Signature::new(
            self.proof.clone(),
            self.public_key.clone(),
            message.to_vec(),
        );
        signature.verify(scheme)?;

        // 2. Bind the signing key to the claimed owner address.
        let derived = csv_keys::bip44::derive_address_from_pubkey(&self.public_key, chain)
            .map_err(|e| {
                ProtocolError::SignatureVerificationFailed(format!(
                    "Failed to derive owner address from public key: {}",
                    e
                ))
            })?;
        if derived.as_bytes() != self.owner.as_slice() {
            return Err(ProtocolError::SignatureVerificationFailed(
                "Ownership proof public key does not correspond to the claimed owner address"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

impl CanonicalEncoding for OwnershipProof {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => {
                // MCE: fixed-width byte concatenation
                let mut result = Vec::new();

                // proof: length-prefixed bytes
                result.extend_from_slice(&ManualEncoder::encode_bytes(&self.proof));

                // owner: length-prefixed bytes
                result.extend_from_slice(&ManualEncoder::encode_bytes(&self.owner));

                // scheme: optional 1 byte tag
                match &self.scheme {
                    Some(scheme) => {
                        result.push(1u8);
                        result.extend_from_slice(&scheme.encode_mce()?);
                    }
                    None => {
                        result.push(0u8);
                    }
                }

                // public_key: length-prefixed bytes (appended after scheme; a
                // legacy blob without this trailer decodes to an empty key)
                result.extend_from_slice(&ManualEncoder::encode_bytes(&self.public_key));

                Ok(result)
            }
            EncodingFormat::ManualBinary => {
                // Manual binary: same as MCE for now
                self.encode(EncodingFormat::MCE)
            }
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        let mut pos = 0;

        // proof: length-prefixed bytes
        let proof = ManualEncoder::decode_bytes(bytes, &mut pos)?;

        // owner: length-prefixed bytes
        let owner = ManualEncoder::decode_bytes(bytes, &mut pos)?;

        // scheme: optional 1 byte tag
        if bytes.len() < pos + 1 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for scheme flag".to_string(),
            ));
        }
        let scheme_flag = bytes[pos];
        pos += 1;

        let scheme = if scheme_flag == 1 {
            if bytes.len() < pos + 1 {
                return Err(CodecError::DeserializationError(
                    "Insufficient bytes for scheme tag".to_string(),
                ));
            }
            let scheme_bytes = &bytes[pos..pos + 1];
            pos += 1;
            Some(SignatureScheme::decode_mce(scheme_bytes)?)
        } else {
            None
        };

        // public_key: length-prefixed bytes. Backward-compatible: a legacy
        // encoding that predates this field ends here, so an absent trailer
        // decodes to an empty public key (which fails closed on verify()).
        let public_key = if pos < bytes.len() {
            ManualEncoder::decode_bytes(bytes, &mut pos)?
        } else {
            Vec::new()
        };

        Ok(Self {
            proof,
            owner,
            scheme,
            public_key,
        })
    }
}

/// A verifiable, single-use digital Sanad (client-side state).
///
/// The Sanad binds a payload descriptor to a commitment and owner.
/// The Sanad ID is derived from the descriptor hash, commitment, and salt,
/// ensuring content metadata is cryptographically bound to the identity.
///
/// **Layer:** L1
/// **Serde:** FORBIDDEN - uses manual CanonicalEncoding via csv-codec
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sanad {
    /// Unique Sanad identifier (domain-separated hash of descriptor || commitment || salt)
    pub id: SanadIdWire,
    /// Commitment hash binding state
    pub commitment: HashWire,
    /// Ownership proof
    pub owner: OwnershipProof,
    /// Salt used in ID derivation
    pub salt: Vec<u8>,
    /// Consumption nullifier when the Sanad seal has been spent
    pub nullifier: Option<HashWire>,
    /// The payload descriptor hash (bound into SanadId)
    pub descriptor_hash: HashWire,
}

impl Sanad {
    /// Create a new Sanad from a payload descriptor, commitment, owner proof, and salt.
    ///
    /// The Sanad ID is derived via domain-separated tagged hashing:
    /// ```text
    /// SanadId = tagged_hash("csv.sanad.id.v1", descriptor_hash || commitment || salt)
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `descriptor` — The payload descriptor binding content metadata
    /// * `commitment` — The commitment hash
    /// * `owner` — The ownership proof
    /// * `salt` — Salt bytes for uniqueness
    pub fn new(
        descriptor: &SanadPayloadDescriptor,
        commitment: Hash,
        owner: OwnershipProof,
        salt: &[u8],
    ) -> Self {
        let descriptor_hash = descriptor.compute_hash();
        // v2: bind the owner identity into the SanadId so a Sanad's identity is
        // cryptographically tied to who owns it (SANAD-OWNERSHIP-PROOF-VERIFY-001).
        let id = SanadId::from_descriptor_commitment_owner(
            descriptor_hash,
            commitment,
            salt,
            &owner.owner,
        );
        Self {
            id: id.into(),
            commitment: commitment.into(),
            owner,
            salt: salt.to_vec(),
            nullifier: None,
            descriptor_hash: descriptor_hash.into(),
        }
    }

    /// Create from an existing commitment object.
    pub fn from_commitment(
        descriptor: &SanadPayloadDescriptor,
        commitment: &Commitment,
        owner: OwnershipProof,
        salt: &[u8],
    ) -> Self {
        Self::new(descriptor, commitment.commitment_hash(), owner, salt)
    }

    /// Serialize to canonical bytes using manual encoding.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.encode_mce()
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }

    /// Deserialize from canonical bytes using manual encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_mce(bytes).map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }
}

impl CanonicalEncoding for Sanad {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => {
                // MCE: fixed-width byte concatenation
                let mut result = Vec::new();

                // id: length-prefixed bytes
                let id_bytes = sanad_id_field(&self.id, "id")?;
                result.extend_from_slice(&ManualEncoder::encode_bytes(&id_bytes));

                // commitment: 32 bytes
                result.extend_from_slice(&hash_field(&self.commitment, "commitment")?);

                // owner: length-prefixed bytes
                result.extend_from_slice(&ManualEncoder::encode_bytes(&self.owner.encode_mce()?));

                // salt: length-prefixed bytes
                result.extend_from_slice(&ManualEncoder::encode_bytes(&self.salt));

                // nullifier: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.nullifier.as_ref(), "nullifier")?,
                ));

                // descriptor_hash: 32 bytes
                result.extend_from_slice(&hash_field(&self.descriptor_hash, "descriptor_hash")?);

                Ok(result)
            }
            EncodingFormat::ManualBinary => {
                // Manual binary: same as MCE for now
                self.encode(EncodingFormat::MCE)
            }
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        let mut pos = 0;

        // id: length-prefixed bytes
        let id_bytes = ManualEncoder::decode_bytes(bytes, &mut pos)?;
        let id = SanadIdWire {
            bytes: hex::encode(id_bytes),
        };

        // commitment: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for commitment".to_string(),
            ));
        }
        let mut commitment_arr = [0u8; 32];
        commitment_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let commitment = HashWire {
            bytes: hex::encode(commitment_arr),
        };
        pos += 32;

        // owner: length-prefixed bytes
        let owner_bytes = ManualEncoder::decode_bytes(bytes, &mut pos)?;
        let owner = OwnershipProof::decode_mce(&owner_bytes)?;

        // salt: length-prefixed bytes
        let salt = ManualEncoder::decode_bytes(bytes, &mut pos)?;

        // nullifier: optional 32 bytes
        let nullifier = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // descriptor_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for descriptor_hash".to_string(),
            ));
        }
        let mut descriptor_hash_arr = [0u8; 32];
        descriptor_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let descriptor_hash = HashWire {
            bytes: hex::encode(descriptor_hash_arr),
        };

        Ok(Self {
            id,
            commitment,
            owner,
            salt,
            nullifier,
            descriptor_hash,
        })
    }
}

/// Wire-format Sanad envelope (golden corpus schema `csv.sanad.envelope.v1`).
///
/// **Layer:** L1
/// **Serde:** FORBIDDEN - uses manual CanonicalEncoding via csv-codec
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanadEnvelope {
    /// Envelope schema version
    pub version: u8,
    /// Registered schema identifier
    pub schema_id: String,
    /// Sanad identity hash
    pub sanad_id: HashWire,
    /// Payload content hash
    pub payload_hash: HashWire,
    /// Optional Merkle root over content subtrees
    pub merkle_root: Option<HashWire>,
    /// Descriptor hash (new in v2)
    pub descriptor_hash: Option<HashWire>,
}

impl SanadEnvelope {
    /// Canonical schema id for envelopes (with descriptor).
    pub const SCHEMA_ID: &'static str = "csv.sanad.envelope.v2";

    /// Build envelope from a [`Sanad`].
    ///
    /// Fails closed if the Sanad's id is not a well-formed 32-byte hash, rather
    /// than emitting an envelope whose `sanad_id` is all zeros
    /// (`DECODE-ZEROFILL-FAILCLOSED-001`).
    pub fn from_sanad(sanad: &Sanad) -> Result<Self> {
        let id = sanad
            .id
            .to_sanad_id()
            .map_err(|e| ProtocolError::SerializationError(format!("Invalid Sanad id: {}", e)))?;

        Ok(Self {
            version: 2,
            schema_id: Self::SCHEMA_ID.to_string(),
            sanad_id: HashWire {
                bytes: hex::encode(id.as_bytes()),
            },
            payload_hash: sanad.commitment.clone(),
            merkle_root: None,
            descriptor_hash: Some(sanad.descriptor_hash.clone()),
        })
    }
}

impl CanonicalEncoding for SanadEnvelope {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => {
                // MCE: fixed-width byte concatenation
                let mut result = Vec::new();

                // version: 1 byte
                result.push(self.version);

                // schema_id: length-prefixed string
                let schema_id_bytes = self.schema_id.as_bytes();
                result
                    .extend_from_slice(&ManualEncoder::encode_u32_le(schema_id_bytes.len() as u32));
                result.extend_from_slice(schema_id_bytes);

                // sanad_id: 32 bytes
                result.extend_from_slice(&hash_field(&self.sanad_id, "sanad_id")?);

                // payload_hash: 32 bytes
                result.extend_from_slice(&hash_field(&self.payload_hash, "payload_hash")?);

                // merkle_root: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.merkle_root.as_ref(), "merkle_root")?,
                ));

                // descriptor_hash: optional 32 bytes
                result.extend_from_slice(&ManualEncoder::encode_option_bytes(
                    &optional_hash_field(self.descriptor_hash.as_ref(), "descriptor_hash")?,
                ));

                Ok(result)
            }
            EncodingFormat::ManualBinary => {
                // Manual binary: same as MCE for now
                self.encode(EncodingFormat::MCE)
            }
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        let mut pos = 0;

        // version: 1 byte
        if bytes.len() < pos + 1 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for version".to_string(),
            ));
        }
        let version = bytes[pos];
        pos += 1;

        // schema_id: length-prefixed string
        let schema_id_len = ManualEncoder::decode_u32_le(bytes, &mut pos)?;
        if bytes.len() < pos + schema_id_len as usize {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for schema_id".to_string(),
            ));
        }
        let schema_id = String::from_utf8(bytes[pos..pos + schema_id_len as usize].to_vec())
            .map_err(|e| {
                CodecError::DeserializationError(format!("Invalid UTF-8 for schema_id: {}", e))
            })?;
        pos += schema_id_len as usize;

        // sanad_id: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for sanad_id".to_string(),
            ));
        }
        let mut sanad_id_arr = [0u8; 32];
        sanad_id_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let sanad_id = HashWire {
            bytes: hex::encode(sanad_id_arr),
        };
        pos += 32;

        // payload_hash: 32 bytes
        if bytes.len() < pos + 32 {
            return Err(CodecError::DeserializationError(
                "Insufficient bytes for payload_hash".to_string(),
            ));
        }
        let mut payload_hash_arr = [0u8; 32];
        payload_hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
        let payload_hash = HashWire {
            bytes: hex::encode(payload_hash_arr),
        };
        pos += 32;

        // merkle_root: optional 32 bytes
        let merkle_root = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        // descriptor_hash: optional 32 bytes
        let descriptor_hash = ManualEncoder::decode_option_bytes(bytes, &mut pos)?.map(|b| {
            let mut arr = [0u8; 32];
            if b.len() == 32 {
                arr.copy_from_slice(&b);
            }
            HashWire {
                bytes: hex::encode(arr),
            }
        });

        Ok(Self {
            version,
            schema_id,
            sanad_id,
            payload_hash,
            merkle_root,
            descriptor_hash,
        })
    }
}

/// Protocol schema version constant (compatibility).
pub const SCHEMA_VERSION: u8 = 2;

/// Minimal schema descriptor for SDK consumers.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub id: String,
    pub version: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::Hash;

    /// Build a valid Ed25519 ownership proof for a given chain, binding the
    /// signer's key to its derived address.
    fn valid_ed25519_proof(
        chain: &csv_hash::ChainId,
        key_byte: u8,
        descriptor_hash: &Hash,
        commitment: &Hash,
        salt: &[u8],
    ) -> OwnershipProof {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[key_byte; 32]);
        let pubkey = signing.verifying_key().to_bytes().to_vec();
        let owner = csv_keys::bip44::derive_address_from_pubkey(&pubkey, chain)
            .unwrap()
            .into_bytes();
        let message = OwnershipProof::signing_message(descriptor_hash, commitment, salt, &owner);
        let sig = signing.sign(&message).to_bytes().to_vec();
        OwnershipProof {
            proof: sig,
            owner,
            scheme: Some(SignatureScheme::Ed25519),
            public_key: pubkey,
        }
    }

    #[test]
    fn test_ownership_proof_valid_verifies() {
        let chain = csv_hash::ChainId::new("sui");
        let descriptor_hash = Hash::new([9u8; 32]);
        let commitment = Hash::new([8u8; 32]);
        let salt = b"salt-xyz";
        let proof = valid_ed25519_proof(&chain, 7, &descriptor_hash, &commitment, salt);
        assert!(
            proof
                .verify(&chain, &descriptor_hash, &commitment, salt)
                .is_ok()
        );
    }

    #[test]
    fn test_ownership_proof_tampered_owner_rejected() {
        // Keep a valid signature/key but swap the owner to a different address:
        // the pubkey no longer derives to `owner`, so verification fails closed.
        let chain = csv_hash::ChainId::new("solana");
        let descriptor_hash = Hash::new([1u8; 32]);
        let commitment = Hash::new([2u8; 32]);
        let salt = b"salt";
        let mut proof = valid_ed25519_proof(&chain, 3, &descriptor_hash, &commitment, salt);
        proof.owner = b"SomeOtherSolanaAddress1111111111111111111111".to_vec();
        assert!(
            proof
                .verify(&chain, &descriptor_hash, &commitment, salt)
                .is_err()
        );
    }

    #[test]
    fn test_ownership_proof_wrong_message_rejected() {
        // A signature over a different commitment must not verify.
        let chain = csv_hash::ChainId::new("aptos");
        let descriptor_hash = Hash::new([4u8; 32]);
        let commitment = Hash::new([5u8; 32]);
        let salt = b"salt";
        let proof = valid_ed25519_proof(&chain, 6, &descriptor_hash, &commitment, salt);
        let other_commitment = Hash::new([0x55u8; 32]);
        assert!(
            proof
                .verify(&chain, &descriptor_hash, &other_commitment, salt)
                .is_err()
        );
    }

    #[test]
    fn test_ownership_proof_missing_pubkey_fails_closed() {
        let chain = csv_hash::ChainId::new("sui");
        let descriptor_hash = Hash::new([1u8; 32]);
        let commitment = Hash::new([2u8; 32]);
        let salt = b"salt";
        let mut proof = valid_ed25519_proof(&chain, 2, &descriptor_hash, &commitment, salt);
        proof.public_key = vec![];
        assert!(
            proof
                .verify(&chain, &descriptor_hash, &commitment, salt)
                .is_err()
        );
    }

    #[test]
    fn test_ownership_proof_roundtrip_preserves_pubkey() {
        let chain = csv_hash::ChainId::new("sui");
        let descriptor_hash = Hash::new([1u8; 32]);
        let commitment = Hash::new([2u8; 32]);
        let salt = b"salt";
        let proof = valid_ed25519_proof(&chain, 2, &descriptor_hash, &commitment, salt);
        let encoded = proof.encode_mce().unwrap();
        let decoded = OwnershipProof::decode_mce(&encoded).unwrap();
        assert_eq!(proof, decoded);
        assert!(!decoded.public_key.is_empty());
    }

    #[test]
    fn test_descriptor_hash_is_deterministic() {
        let desc = SanadPayloadDescriptor::new(
            "test.schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let h1 = desc.compute_hash();
        let h2 = desc.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sanad_id_uses_descriptor() {
        let desc1 = SanadPayloadDescriptor::new(
            "schema1",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let desc2 = SanadPayloadDescriptor::new(
            "schema2",
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
            None,
            Hash::new([7u8; 32]),
            Hash::new([8u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let salt = b"test-salt";

        let id1 = SanadId::from_descriptor_commitment(desc1.compute_hash(), commitment, salt);
        let id2 = SanadId::from_descriptor_commitment(desc2.compute_hash(), commitment, salt);

        // Different descriptors produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sanad_id_uses_salt() {
        let desc = SanadPayloadDescriptor::new(
            "schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let salt1 = b"salt-1";
        let salt2 = b"salt-2";

        let id1 = SanadId::from_descriptor_commitment(desc.compute_hash(), commitment, salt1);
        let id2 = SanadId::from_descriptor_commitment(desc.compute_hash(), commitment, salt2);

        // Different salts produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sanad_new_includes_descriptor_hash() {
        let desc = SanadPayloadDescriptor::new(
            "schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let owner = OwnershipProof {
            proof: vec![0u8; 32],
            owner: vec![0u8; 32],
            scheme: None,
            public_key: vec![],
        };
        let salt = b"test-salt";

        let sanad = Sanad::new(&desc, commitment, owner, salt);
        assert_eq!(sanad.descriptor_hash, HashWire::from(desc.compute_hash()));
    }

    #[test]
    fn test_sanad_with_zero_descriptor_hash() {
        let commitment = Hash::new([0xAAu8; 32]);
        let descriptor = SanadPayloadDescriptor::new(
            SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        );
        let owner = OwnershipProof {
            proof: vec![0u8; 32],
            owner: vec![0u8; 32],
            scheme: None,
            public_key: vec![],
        };
        let salt = b"test-salt";

        let sanad = Sanad::new(&descriptor, commitment, owner, salt);
        // The descriptor_hash should be the hash of the descriptor, not zero
        assert_ne!(sanad.descriptor_hash, HashWire::from(Hash::new([0u8; 32])));
        // Verify the descriptor_hash matches the descriptor's compute_hash
        assert_eq!(sanad.descriptor_hash, descriptor.compute_hash().into());
    }
}
