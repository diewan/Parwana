//! Hex-string serde helper for binary wire fields.
//!
//! Keeps the wire crate's convention (binary fields serialize as lowercase hex
//! strings) available to `#[serde(with = "crate::hexbytes")]` fields. The canonical
//! hashing form is CBOR (`csv-codec`); this only governs the human/transport shape.

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte slice as a lowercase hex string.
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize a lowercase hex string into a byte vector.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(serde::de::Error::custom)
}
