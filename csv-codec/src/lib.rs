//! CSV Codec - Canonical serialization, deterministic decoding, schema validation, byte ordering
//!
//! This crate provides canonical CBOR serialization for the Parwana.
//! All protocol-critical data must be serialized using this crate to ensure
//! determinism and cross-chain compatibility.
//!
//! # Canonical Encoding Rules
//! - Little endian ONLY for all integer types
//! - Fixed field ordering (lexicographic for maps)
//! - Explicit enum tags
//! - Explicit version tags
//! - Deterministic maps/arrays (sorted keys)
//! - Canonical UTF-8 (NFC normalized, no BOM)
//! - No floats in protocol state

#![warn(missing_docs)]

pub mod byte_order;
pub mod canonical;
pub mod decode;
pub mod encode;
pub mod error;
pub mod manual_encoder;
pub mod schema;
pub mod versioning;

// Re-exports
pub use canonical::{
    CBOR_TAG_RANGE_END, CBOR_TAG_RANGE_START, canonical_hash, cbor_tags, from_canonical_cbor,
    from_canonical_cbor_full, from_canonical_cbor_with_checksum, to_canonical_cbor,
    to_canonical_cbor_with_checksum, to_canonical_cbor_with_tag,
};
pub use error::{CodecError, Result as CodecResult};
pub use manual_encoder::{CanonicalEncoding, EncodingFormat, MCEEncoder, ManualEncoder};
pub use versioning::{
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR, PROTOCOL_VERSION_PATCH, ProtocolVersion,
};
