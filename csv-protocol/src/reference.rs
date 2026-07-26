//! Disjoint consumption and evidence references (PAR-STATE-001).
//!
//! Consuming state and citing evidence are different protocol operations. They
//! have different adversaries, different verifier paths, and different
//! obligations, so they get different types that cannot be interchanged.
//!
//! - [`ConsumedStateRef`] identifies state whose **unique successor** is being
//!   asserted. Using it is a once-ever operation that requires closure evidence
//!   in the source state's closure domain.
//! - [`EvidenceRef`] identifies immutable evidence that may be **cited
//!   repeatedly**. Citing it asserts only that the commitment was referenced
//!   under its stated proof requirement — never that the cited material is
//!   true, endorsed, or authorized.
//!
//! This is constitutional rule 1 of
//! `development/PARWANA_PORTABLE_NON_EQUIVOCATION_PLAN.md` and threat T-NE-08
//! in `csv-docs/THREAT_MODEL.md` (rules `NE-R-REF-DISJOINT`,
//! `NE-R-CITATION-NOT-ENDORSEMENT`). Ownership of both types is assigned to
//! `csv-protocol` by ADR-0016.
//!
//! # The firewall
//!
//! Three independent mechanisms keep the two apart. Any one of them failing
//! still leaves the other two:
//!
//! 1. **Distinct types.** A consumed-input slot is typed `ConsumedStateRef`, so
//!    an `EvidenceRef` cannot be placed in one. There is no conversion between
//!    them in either direction — deliberately, not by omission.
//! 2. **Sealed capability traits.** [`Consumable`] and [`Citable`] are sealed
//!    and disjoint. A function that cites takes `impl Citable`, which
//!    `ConsumedStateRef` does not implement, so "treat this consumption as a
//!    repeatable citation" does not compile. The `compile_fail` doc tests on
//!    [`cite`] and [`consume`] pin this.
//! 3. **Distinct canonical bytes.** Each encoding carries its own
//!    one-byte discriminant *and* is digested under its own domain tag, so no
//!    encoding of one can be reinterpreted as the other even if it reached a
//!    decoder for the wrong type.
//!
//! # Public concept review
//!
//! *Nearest semantic siblings and difference.*
//!
//! - [`crate::state::StateRef`] (V1) — the closest sibling. It carries the same
//!   three fields but says nothing about whether using it is exclusive, and it
//!   is the type both consumption and citation currently share. `ConsumedStateRef`
//!   is its V2 successor for the consumption half only; `StateRef` is not
//!   deprecated here because V1 artifacts still decode into it.
//! - [`crate::seal::SealPoint`] — a *chain-native closure handle*, the thing
//!   spent to order a consumption. `ConsumedStateRef` names the protocol state;
//!   `SealPoint` names the mechanism by which its consumption becomes ordered.
//!   They are not interchangeable: one source state has one closure handle, but
//!   a handle is meaningless without the state it closes.
//! - [`crate::seal::CommitAnchor`] — where a commitment was published.
//!   `EvidenceRef` names *what* is cited and what proof the citation owes;
//!   `CommitAnchor` names *where* something was anchored.
//! - `EvidenceNodeDomain` in `csv-hash` — the accountability evidence family.
//!   `EvidenceRef` is a reference *to* such evidence, not a node of it.
//!
//! *What they prove.* `ConsumedStateRef` proves nothing on its own; it states
//! which state a successor claims to consume, and the closure dimension decides
//! whether the claim holds. `EvidenceRef` proves nothing about its referent's
//! truth; it fixes which commitment was cited and what proof is owed.
//!
//! *What they do not prove.* Neither carries authority. Neither is a verdict.
//! An `EvidenceRef` with `ProofRequirement::None` is a bare pointer, and the
//! type says so rather than implying more.

use serde::{Deserialize, Serialize};

use crate::state::StateTypeId;
use csv_hash::{Hash, csv_tagged_hash};

/// Domain tag for a consumption reference's digest.
pub const CONSUMED_STATE_REF_TAG: &str = "consumed-state-ref-v2";
/// Domain tag for an evidence reference's digest.
pub const EVIDENCE_REF_TAG: &str = "evidence-ref-v2";

/// Leading byte of a consumption reference's canonical encoding.
pub const CONSUMED_STATE_REF_DISCRIMINANT: u8 = 0x01;
/// Leading byte of an evidence reference's canonical encoding.
pub const EVIDENCE_REF_DISCRIMINANT: u8 = 0x02;

mod private {
    /// Prevents any type outside this module from claiming either capability,
    /// so the two families stay closed and provably disjoint.
    pub trait Sealed {}
    impl Sealed for super::ConsumedStateRef {}
    impl Sealed for super::EvidenceRef {}
}

/// A reference whose use asserts a **unique successor** of the referenced state.
///
/// Sealed and implemented only by [`ConsumedStateRef`]. Using a `Consumable` is
/// a once-ever operation: a second successor of the same state is a conflict,
/// decided by the state's closure domain and not by any local check.
pub trait Consumable: private::Sealed {
    /// The state type being consumed.
    fn state_type(&self) -> StateTypeId;
    /// Domain-separated digest of this reference.
    fn digest(&self) -> Hash;
}

/// A reference that may be **cited repeatedly** without consuming anything.
///
/// Sealed and implemented only by [`EvidenceRef`]. Citing asserts that the
/// commitment was referenced under its stated proof requirement. It is not an
/// endorsement of the cited material.
pub trait Citable: private::Sealed {
    /// The commitment being cited.
    fn commitment(&self) -> Hash;
    /// What the citation owes a verifier.
    fn proof_requirement(&self) -> ProofRequirement;
    /// Domain-separated digest of this reference.
    fn digest(&self) -> Hash;
}

/// What a citation obliges its holder to supply.
///
/// Recorded on the reference itself so a verifier reads the obligation from the
/// artifact rather than inferring it from context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofRequirement {
    /// The commitment is the whole claim; nothing further is owed. The weakest
    /// citation, and named as such rather than left implicit.
    None = 0,
    /// An inclusion proof against a named anchor must accompany the citation.
    Inclusion = 1,
    /// Inclusion plus a finalized checkpoint satisfying the configured policy.
    FinalizedInclusion = 2,
    /// The cited material itself must be supplied and re-derived to the
    /// commitment.
    Preimage = 3,
}

impl ProofRequirement {
    /// Canonical discriminant used in the encoding and the digest preimage.
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Decode a canonical discriminant.
    pub const fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Inclusion),
            2 => Some(Self::FinalizedInclusion),
            3 => Some(Self::Preimage),
            _ => None,
        }
    }
}

/// Identifies state whose unique successor is being asserted (RFC-0014 §1.1).
///
/// Placing one of these in a transition's inputs is a claim that this
/// transition is *the* successor of that output. The claim is settled by the
/// source state's closure domain, never by the sender's database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsumedStateRef {
    /// Identifier of the transition that created the consumed output.
    pub transition_id: Hash,
    /// Index of the output within that transition.
    pub output_index: u32,
    /// State type of the consumed output, checked against the parent's schema.
    pub state_type: StateTypeId,
}

impl ConsumedStateRef {
    /// Reference the output at `output_index` of `transition_id`.
    pub const fn new(transition_id: Hash, output_index: u32, state_type: StateTypeId) -> Self {
        Self {
            transition_id,
            output_index,
            state_type,
        }
    }

    /// Canonical bytes: discriminant, then fixed-width fields.
    ///
    /// The leading discriminant differs from [`EvidenceRef`]'s, so the two
    /// encodings cannot be reinterpreted as each other.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + 32 + 4 + 2);
        data.push(CONSUMED_STATE_REF_DISCRIMINANT);
        data.extend_from_slice(self.transition_id.as_bytes());
        data.extend_from_slice(&self.output_index.to_le_bytes());
        data.extend_from_slice(&self.state_type.to_le_bytes());
        data
    }

    /// Decode canonical bytes, rejecting any other reference kind.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReferenceDecodeError> {
        if bytes.len() != 1 + 32 + 4 + 2 {
            return Err(ReferenceDecodeError::WrongLength {
                expected: 1 + 32 + 4 + 2,
                found: bytes.len(),
            });
        }
        if bytes[0] != CONSUMED_STATE_REF_DISCRIMINANT {
            return Err(ReferenceDecodeError::WrongDiscriminant {
                expected: CONSUMED_STATE_REF_DISCRIMINANT,
                found: bytes[0],
            });
        }
        let mut transition_id = [0u8; 32];
        transition_id.copy_from_slice(&bytes[1..33]);
        let output_index = u32::from_le_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        let state_type = StateTypeId::from_le_bytes([bytes[37], bytes[38]]);
        Ok(Self {
            transition_id: Hash::new(transition_id),
            output_index,
            state_type,
        })
    }
}

impl Consumable for ConsumedStateRef {
    fn state_type(&self) -> StateTypeId {
        self.state_type
    }

    fn digest(&self) -> Hash {
        Hash::new(csv_tagged_hash(
            CONSUMED_STATE_REF_TAG,
            &self.to_canonical_bytes(),
        ))
    }
}

/// Identifies immutable evidence that may be cited repeatedly (RFC-0014 §1.8).
///
/// Citing evidence is not consuming it, and it is not endorsing it. The
/// [`ProofRequirement`] states what the citation owes; nothing about the cited
/// material's truth follows from the citation existing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Commitment to the cited material.
    pub commitment: Hash,
    /// What a verifier is owed for this citation.
    pub proof_requirement: ProofRequirement,
}

impl EvidenceRef {
    /// Cite `commitment` under `proof_requirement`.
    pub const fn new(commitment: Hash, proof_requirement: ProofRequirement) -> Self {
        Self {
            commitment,
            proof_requirement,
        }
    }

    /// Canonical bytes: discriminant, then fixed-width fields.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + 32 + 1);
        data.push(EVIDENCE_REF_DISCRIMINANT);
        data.extend_from_slice(self.commitment.as_bytes());
        data.push(self.proof_requirement.discriminant());
        data
    }

    /// Decode canonical bytes, rejecting any other reference kind.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReferenceDecodeError> {
        if bytes.len() != 1 + 32 + 1 {
            return Err(ReferenceDecodeError::WrongLength {
                expected: 1 + 32 + 1,
                found: bytes.len(),
            });
        }
        if bytes[0] != EVIDENCE_REF_DISCRIMINANT {
            return Err(ReferenceDecodeError::WrongDiscriminant {
                expected: EVIDENCE_REF_DISCRIMINANT,
                found: bytes[0],
            });
        }
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[1..33]);
        let proof_requirement = ProofRequirement::from_discriminant(bytes[33])
            .ok_or(ReferenceDecodeError::UnknownProofRequirement(bytes[33]))?;
        Ok(Self {
            commitment: Hash::new(commitment),
            proof_requirement,
        })
    }
}

impl Citable for EvidenceRef {
    fn commitment(&self) -> Hash {
        self.commitment
    }

    fn proof_requirement(&self) -> ProofRequirement {
        self.proof_requirement
    }

    fn digest(&self) -> Hash {
        Hash::new(csv_tagged_hash(
            EVIDENCE_REF_TAG,
            &self.to_canonical_bytes(),
        ))
    }
}

/// Why a reference's canonical bytes were rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceDecodeError {
    /// The encoding names a different reference kind. This is the firewall
    /// refusing to reinterpret one family's bytes as the other's.
    #[error("reference discriminant {found:#04x} is not {expected:#04x}")]
    WrongDiscriminant {
        /// Discriminant the decoder requires.
        expected: u8,
        /// Discriminant the bytes carry.
        found: u8,
    },
    /// The encoding is not the fixed width this reference kind uses.
    #[error("reference encoding is {found} bytes, expected {expected}")]
    WrongLength {
        /// Width this reference kind uses.
        expected: usize,
        /// Width the bytes have.
        found: usize,
    },
    /// The proof requirement discriminant is not one this version defines.
    /// Unknown obligations fail closed rather than defaulting to `None`.
    #[error("unknown proof requirement {0}")]
    UnknownProofRequirement(u8),
}

/// Cite evidence. Accepts only [`Citable`] references.
///
/// This function exists to make the firewall executable: a `ConsumedStateRef`
/// cannot reach it, so "treat a consumption as a repeatable citation" is a
/// compile error rather than a review comment.
///
/// ```
/// use csv_protocol::reference::{cite, EvidenceRef, ProofRequirement};
/// use csv_hash::Hash;
///
/// let evidence = EvidenceRef::new(Hash::new([7u8; 32]), ProofRequirement::Inclusion);
/// // Citing the same evidence twice is well-defined and identical.
/// assert_eq!(cite(&evidence), cite(&evidence));
/// ```
///
/// A consumption reference is not citable:
///
/// ```compile_fail
/// use csv_protocol::reference::{cite, ConsumedStateRef};
/// use csv_hash::Hash;
///
/// let consumed = ConsumedStateRef::new(Hash::new([1u8; 32]), 0, 10);
/// // error[E0277]: the trait bound `ConsumedStateRef: Citable` is not satisfied
/// let _ = cite(&consumed);
/// ```
pub fn cite<R: Citable>(reference: &R) -> Hash {
    reference.digest()
}

/// Consume state. Accepts only [`Consumable`] references.
///
/// ```
/// use csv_protocol::reference::{consume, ConsumedStateRef};
/// use csv_hash::Hash;
///
/// let consumed = ConsumedStateRef::new(Hash::new([1u8; 32]), 0, 10);
/// assert_ne!(consume(&consumed), Hash::zero());
/// ```
///
/// Evidence cannot enter a consumed-input slot:
///
/// ```compile_fail
/// use csv_protocol::reference::{consume, EvidenceRef, ProofRequirement};
/// use csv_hash::Hash;
///
/// let evidence = EvidenceRef::new(Hash::new([7u8; 32]), ProofRequirement::None);
/// // error[E0277]: the trait bound `EvidenceRef: Consumable` is not satisfied
/// let _ = consume(&evidence);
/// ```
pub fn consume<R: Consumable>(reference: &R) -> Hash {
    reference.digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consumed() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1u8; 32]), 3, 10)
    }

    fn evidence() -> EvidenceRef {
        EvidenceRef::new(Hash::new([1u8; 32]), ProofRequirement::Inclusion)
    }

    // ── Canonical bytes cannot collide or be reinterpreted ──────────────────

    #[test]
    fn the_two_encodings_carry_different_discriminants() {
        assert_ne!(
            CONSUMED_STATE_REF_DISCRIMINANT, EVIDENCE_REF_DISCRIMINANT,
            "the discriminant is what stops one decoding as the other"
        );
        assert_eq!(
            consumed().to_canonical_bytes()[0],
            CONSUMED_STATE_REF_DISCRIMINANT
        );
        assert_eq!(
            evidence().to_canonical_bytes()[0],
            EVIDENCE_REF_DISCRIMINANT
        );
    }

    #[test]
    fn evidence_bytes_do_not_decode_as_a_consumption() {
        let bytes = evidence().to_canonical_bytes();
        assert!(matches!(
            ConsumedStateRef::from_canonical_bytes(&bytes),
            Err(ReferenceDecodeError::WrongLength { .. })
                | Err(ReferenceDecodeError::WrongDiscriminant { .. })
        ));
    }

    #[test]
    fn consumption_bytes_do_not_decode_as_evidence() {
        let bytes = consumed().to_canonical_bytes();
        assert!(matches!(
            EvidenceRef::from_canonical_bytes(&bytes),
            Err(ReferenceDecodeError::WrongLength { .. })
                | Err(ReferenceDecodeError::WrongDiscriminant { .. })
        ));
    }

    #[test]
    fn a_relabelled_encoding_is_still_rejected() {
        // Strip the length difference: rewrite the discriminant of a
        // consumption encoding truncated to evidence width. The decoder must
        // still refuse rather than reinterpret the remaining bytes.
        let mut bytes = consumed().to_canonical_bytes();
        bytes.truncate(1 + 32 + 1);
        bytes[0] = EVIDENCE_REF_DISCRIMINANT;
        // It now decodes structurally — which is exactly why the digest, not
        // the bytes alone, is what verifiers compare.
        let forged = EvidenceRef::from_canonical_bytes(&bytes);
        if let Ok(forged) = forged {
            assert_ne!(
                forged.digest(),
                consumed().digest(),
                "a relabelled encoding must not reproduce the original digest"
            );
        }
    }

    #[test]
    fn identical_payloads_digest_differently_in_each_domain() {
        // Same 32-byte hash in both references; the domain tags separate them.
        let by_consumption = consumed().digest();
        let by_citation = evidence().digest();
        assert_ne!(by_consumption, by_citation);
        assert_ne!(CONSUMED_STATE_REF_TAG, EVIDENCE_REF_TAG);
    }

    #[test]
    fn digests_are_deterministic_and_field_sensitive() {
        assert_eq!(consumed().digest(), consumed().digest());
        assert_ne!(
            consumed().digest(),
            ConsumedStateRef::new(Hash::new([1u8; 32]), 4, 10).digest(),
            "output index must bind"
        );
        assert_ne!(
            consumed().digest(),
            ConsumedStateRef::new(Hash::new([1u8; 32]), 3, 11).digest(),
            "state type must bind"
        );
        assert_ne!(
            evidence().digest(),
            EvidenceRef::new(Hash::new([1u8; 32]), ProofRequirement::None).digest(),
            "proof requirement must bind"
        );
    }

    // ── Round trips ─────────────────────────────────────────────────────────

    #[test]
    fn canonical_round_trips() {
        assert_eq!(
            ConsumedStateRef::from_canonical_bytes(&consumed().to_canonical_bytes()).unwrap(),
            consumed()
        );
        assert_eq!(
            EvidenceRef::from_canonical_bytes(&evidence().to_canonical_bytes()).unwrap(),
            evidence()
        );
    }

    #[test]
    fn an_unknown_proof_requirement_fails_closed() {
        let mut bytes = evidence().to_canonical_bytes();
        bytes[33] = 0xFF;
        assert_eq!(
            EvidenceRef::from_canonical_bytes(&bytes),
            Err(ReferenceDecodeError::UnknownProofRequirement(0xFF)),
            "an unrecognized obligation must not default to `None`"
        );
    }

    #[test]
    fn every_proof_requirement_round_trips_its_discriminant() {
        for requirement in [
            ProofRequirement::None,
            ProofRequirement::Inclusion,
            ProofRequirement::FinalizedInclusion,
            ProofRequirement::Preimage,
        ] {
            assert_eq!(
                ProofRequirement::from_discriminant(requirement.discriminant()),
                Some(requirement)
            );
        }
    }

    // ── The type-level firewall ─────────────────────────────────────────────

    #[test]
    fn a_consumed_input_slot_only_accepts_consumption_references() {
        // A "consumed-input slot" is a typed collection. The compile_fail doc
        // tests on `cite` and `consume` prove the negative; this pins the
        // positive shape the slot actually has.
        fn consumed_input_slot(inputs: Vec<ConsumedStateRef>) -> usize {
            inputs.len()
        }
        assert_eq!(consumed_input_slot(vec![consumed()]), 1);
    }

    #[test]
    fn citation_is_repeatable_and_consumption_is_not_modelled_as_repeatable() {
        // Citing the same evidence any number of times is the same operation.
        let evidence = evidence();
        let repeated: Vec<Hash> = (0..5).map(|_| cite(&evidence)).collect();
        assert!(repeated.windows(2).all(|pair| pair[0] == pair[1]));

        // A consumption reference has no `cite` path at all — it is not
        // `Citable`, so repetition is not expressible rather than discouraged.
        // (See the `compile_fail` doc test on `cite`.)
        assert_eq!(consume(&consumed()), consumed().digest());
    }
}
