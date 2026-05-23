//! CSV Codec - Canonical serialization, deterministic decoding, schema validation, byte ordering
//!
//! This crate provides canonical CBOR serialization for the CSV protocol.
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

pub mod canonical;
pub mod schema;
pub mod byte_order;
pub mod error;
pub mod encode;
pub mod decode;
pub mod versioning;

// Re-exports
pub use canonical::{
    to_canonical_cbor, 
    from_canonical_cbor, 
    to_canonical_cbor_with_tag,
    to_canonical_cbor_with_checksum,
    from_canonical_cbor_with_checksum,
    from_canonical_cbor_full,
    cbor_tags,
    CBOR_TAG_RANGE_START,
    CBOR_TAG_RANGE_END,
};
pub use error::{CodecError, Result as CodecResult};
pub use versioning::{ProtocolVersion, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR, PROTOCOL_VERSION_PATCH};
