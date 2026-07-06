//! Recipient-issued invoice for the interactive off-chain transfer mode.
//!
//! An [`Invoice`] is the recipient's request: it binds a [`SealDefinition`] the
//! recipient controls on the destination chain (the RGB blinded-seal analog), the
//! sanad schema/type the recipient will accept, and an anti-replay nonce. Because the
//! seal is recipient-defined, griefing is structurally prevented — a sender can only
//! assign the sanad to the exact seal the recipient nominated.
//!
//! Canonical hashing uses CBOR via `csv-codec`; `serde_json` is never used here.

use csv_codec::{CodecError, canonical_hash, to_canonical_cbor};
use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

use crate::seal::SealDefinition;

/// Current invoice wire version.
pub const INVOICE_VERSION: u16 = 1;

/// Domain tag used when deriving the canonical invoice id.
const INVOICE_ID_DOMAIN: &str = "csv.wire.invoice.v1";

/// A recipient-issued invoice binding a destination seal, an accepted schema, and an
/// anti-replay nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// Invoice wire version.
    pub version: u16,
    /// The recipient-controlled destination seal (RGB blinded-seal analog).
    pub seal: SealDefinition,
    /// Identifier of the sanad schema/type the recipient accepts (e.g. a 32-byte
    /// schema hash). Kept opaque here; interpreted by the schema layer on accept.
    #[serde(with = "crate::hexbytes")]
    pub schema_id: Vec<u8>,
    /// Anti-replay nonce chosen by the recipient. Folded into the bound
    /// [`SealPoint`] so a consignment for one invoice cannot satisfy another.
    pub nonce: u64,
}

impl Invoice {
    /// Create a new invoice at the current [`INVOICE_VERSION`].
    ///
    /// # Errors
    /// Returns an error if `schema_id` is empty.
    pub fn new(seal: SealDefinition, schema_id: Vec<u8>, nonce: u64) -> Result<Self, String> {
        if schema_id.is_empty() {
            return Err("invoice schema_id must not be empty".to_string());
        }
        Ok(Self {
            version: INVOICE_VERSION,
            seal,
            schema_id,
            nonce,
        })
    }

    /// The [`SealPoint`] a satisfying consignment must assign the sanad to, with the
    /// invoice's anti-replay nonce folded in.
    ///
    /// # Errors
    /// Returns an error if the seal definition cannot be reduced to a valid `SealPoint`.
    pub fn bound_seal_point(&self) -> Result<SealPoint, String> {
        self.seal.to_seal_point(Some(self.nonce))
    }

    /// Deterministic CBOR encoding of the invoice.
    ///
    /// # Errors
    /// Returns a [`CodecError`] if canonical encoding fails.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }

    /// Domain-separated canonical id (hash) of the invoice.
    ///
    /// # Errors
    /// Returns a [`CodecError`] if canonical encoding fails.
    pub fn canonical_id(&self) -> Result<Vec<u8>, CodecError> {
        canonical_hash(INVOICE_ID_DOMAIN, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::SealDefinition;
    use csv_codec::from_canonical_cbor;

    fn sample_invoice(nonce: u64) -> Invoice {
        let seal = SealDefinition::sui(vec![0xCD; 32], 7).unwrap();
        Invoice::new(seal, vec![0xAA; 32], nonce).unwrap()
    }

    #[test]
    fn rejects_empty_schema() {
        let seal = SealDefinition::sui(vec![0xCD; 32], 7).unwrap();
        assert!(Invoice::new(seal, vec![], 1).is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        let inv = sample_invoice(99);
        let json = serde_json::to_string(&inv).unwrap();
        let back: Invoice = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn canonical_cbor_round_trip() {
        let inv = sample_invoice(99);
        let cbor = inv.canonical_cbor().unwrap();
        let back: Invoice = from_canonical_cbor(&cbor).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn canonical_cbor_is_deterministic() {
        let inv = sample_invoice(99);
        assert_eq!(inv.canonical_cbor().unwrap(), inv.canonical_cbor().unwrap());
    }

    #[test]
    fn bound_seal_point_folds_nonce() {
        let inv = sample_invoice(0xDEAD);
        let sp = inv.bound_seal_point().unwrap();
        assert_eq!(sp.nonce, Some(0xDEAD));
        assert_eq!(sp.version, Some(7));
    }

    #[test]
    fn nonce_changes_bound_seal_and_canonical_id() {
        let a = sample_invoice(1);
        let b = sample_invoice(2);
        assert_ne!(a.bound_seal_point().unwrap(), b.bound_seal_point().unwrap());
        assert_ne!(a.canonical_id().unwrap(), b.canonical_id().unwrap());
    }
}
