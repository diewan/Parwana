//! Consignment envelope for the interactive off-chain transfer mode.
//!
//! A [`Consignment`] is the portable artifact the sender hands the recipient. It
//! reuses the existing [`ProofBundle`] (which already carries the transition DAG back
//! to a validated anchor, plus inclusion and finality proofs) and pairs it with the
//! [`Invoice`] it satisfies and the sanad being delivered. This replaces the earlier
//! JSON stub; correctness is entirely client-side (`accept`, ticket I3), with no
//! attestor, ZK, or destination gas.
//!
//! Canonical hashing uses CBOR via `csv-codec`; `serde_json` is never used here.

use csv_codec::{CodecError, to_canonical_cbor};
use csv_protocol::proof_taxonomy::ProofBundle;
use serde::{Deserialize, Serialize};

use crate::invoice::Invoice;
use crate::primitives::SanadIdWire;

/// Current consignment envelope wire version.
pub const CONSIGNMENT_VERSION: u16 = 1;

/// The sender-produced envelope delivering a sanad against a recipient invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consignment {
    /// Consignment envelope wire version.
    pub version: u16,
    /// The invoice this consignment satisfies (binds destination seal + nonce).
    pub invoice: Invoice,
    /// The sanad being delivered.
    pub sanad_id: SanadIdWire,
    /// Reused proof bundle: the transition DAG history back to a validated anchor,
    /// plus inclusion and finality proofs. See [`ProofBundle`].
    pub proof_bundle: ProofBundle,
}

impl Consignment {
    /// Create a new consignment at the current [`CONSIGNMENT_VERSION`].
    pub fn new(invoice: Invoice, sanad_id: SanadIdWire, proof_bundle: ProofBundle) -> Self {
        Self {
            version: CONSIGNMENT_VERSION,
            invoice,
            sanad_id,
            proof_bundle,
        }
    }

    /// Deterministic CBOR encoding of the whole envelope.
    ///
    /// # Errors
    /// Returns a [`CodecError`] if canonical encoding fails.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }

    /// Whether the bundled proof assigns the sanad to the exact [`SealPoint`] the
    /// invoice nominated (destination seal + anti-replay nonce). This is the anti-
    /// griefing binding: a consignment for one invoice cannot satisfy another.
    ///
    /// This is a structural check only; full client-side validation (finality, DAG
    /// linkage, replay) lands with `accept` (ticket I3).
    ///
    /// # Errors
    /// Returns an error if the invoice seal cannot be reduced to a `SealPoint`.
    pub fn binds_invoice_seal(&self) -> Result<bool, String> {
        let expected = self.invoice.bound_seal_point()?;
        Ok(self.proof_bundle.seal_ref == expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::SealDefinition;
    use csv_hash::Hash;
    use csv_hash::dag::DAGSegment;
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use csv_protocol::SignatureScheme;
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

    fn sample_invoice() -> Invoice {
        let seal = SealDefinition::sui(vec![0xCD; 32], 7).unwrap();
        Invoice::new(seal, vec![0xAA; 32], 0xBEEF).unwrap()
    }

    fn proof_bundle_with_seal(seal_ref: SealPoint) -> ProofBundle {
        ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], Hash::new([0u8; 32])),
            signatures: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            seal_ref,
            anchor_ref: CommitAnchor {
                anchor_id: vec![0u8; 32],
                block_height: 0,
                metadata: vec![],
            },
            inclusion_proof: InclusionProof {
                proof_bytes: vec![1u8; 32],
                block_hash: Hash::new([1u8; 32]),
                position: 0,
                block_number: 1,
                leaf: Hash::new([3u8; 32]),
                root: Hash::new([4u8; 32]),
                siblings: vec![],
                leaf_index: 0,
                source: "test".to_string(),
            },
            finality_proof: FinalityProof {
                finality_data: vec![1u8; 32],
                block_hash: Hash::new([2u8; 32]),
                threshold: 2,
                confirmations: 6,
                data: vec![2u8; 32],
                source: "test".to_string(),
                is_deterministic: true,
            },
        }
    }

    fn sample_consignment(invoice: Invoice, bind: bool) -> Consignment {
        let seal_ref = if bind {
            invoice.bound_seal_point().unwrap()
        } else {
            SealPoint::new(vec![0xFF; 32], None, None).unwrap()
        };
        Consignment::new(
            invoice,
            SanadIdWire {
                bytes: hex::encode([0x55u8; 32]),
            },
            proof_bundle_with_seal(seal_ref),
        )
    }

    #[test]
    fn canonical_cbor_round_trip() {
        let c = sample_consignment(sample_invoice(), true);
        let cbor = c.canonical_cbor().unwrap();
        let back: Consignment = csv_codec::from_canonical_cbor(&cbor).unwrap();
        assert_eq!(back.version, c.version);
        assert_eq!(back.invoice, c.invoice);
        assert_eq!(back.proof_bundle, c.proof_bundle);
    }

    #[test]
    fn serde_json_round_trip() {
        let c = sample_consignment(sample_invoice(), true);
        let json = serde_json::to_string(&c).unwrap();
        let back: Consignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.invoice, c.invoice);
        assert_eq!(back.proof_bundle, c.proof_bundle);
    }

    #[test]
    fn binds_invoice_seal_detects_match_and_mismatch() {
        let bound = sample_consignment(sample_invoice(), true);
        assert!(bound.binds_invoice_seal().unwrap());

        let unbound = sample_consignment(sample_invoice(), false);
        assert!(!unbound.binds_invoice_seal().unwrap());
    }
}
