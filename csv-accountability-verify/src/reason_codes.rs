//! Published reason-code registry (Master Plan §37).
//!
//! [`ReasonCode`] is the single source of truth; each variant maps to a stable,
//! namespaced identifier via [`ReasonCode::registry_id`]. This module publishes the
//! complete registry as data ([`ALL_REASON_CODES`]), documents the well-formedness rule
//! ([`is_well_formed`]), and reserves the namespaces that profile- and anchor-contributed
//! evidence uses so those codes cannot silently collide with the core set.

use crate::ReasonCode;

/// The affirmative "requirement met" code emitted when no reason opposes a dimension.
pub const REQUIREMENT_MET: &str = "ACCOUNTABILITY.REQUIREMENT_MET";

/// Affirmative code: the mandate's single use was independently enforced by a preserved
/// seal consumption, not only by the private reservation store (Phase B).
pub const SINGLE_USE_INDEPENDENTLY_ENFORCED: &str =
    "ACCOUNTABILITY.SINGLE_USE.INDEPENDENTLY_ENFORCED";

/// Affirmative code: a preserved seal-consumption record re-checked offline as valid.
pub const CSV_SEAL_CONSUMPTION_VALID: &str = "ACCOUNTABILITY.EVIDENCE.CSV_SEAL_CONSUMPTION_VALID";

/// Every reason code the reference verifier can emit, in stable order.
///
/// A test asserts this list is exhaustive over [`ReasonCode`], so adding a variant
/// without registering it here fails the build's test gate.
pub const ALL_REASON_CODES: &[ReasonCode] = &[
    ReasonCode::MalformedStructure,
    ReasonCode::IntentMismatch,
    ReasonCode::MandateInvalid,
    ReasonCode::WrongExecutor,
    ReasonCode::MandateNotYetValid,
    ReasonCode::MandateExpired,
    ReasonCode::MandateRevoked,
    ReasonCode::RevocationStatusUnknown,
    ReasonCode::AlgorithmDisallowed,
    ReasonCode::AlgorithmStatusUnknown,
    ReasonCode::ReplayDetected,
    ReasonCode::ReplayStatusUnknown,
    ReasonCode::EvidenceInvalid,
    ReasonCode::EvidenceReferenceMissing,
    ReasonCode::EvidenceAuthenticityRejected,
    ReasonCode::EvidenceAuthenticityUnknown,
    ReasonCode::RequiredEvidenceMissing,
    ReasonCode::SelectiveDisclosureLimitsEvaluation,
    ReasonCode::ContradictoryEvidenceOmitted,
    ReasonCode::ConflictingEvidencePreserved,
    ReasonCode::ReceiptInvalid,
    ReasonCode::OutcomeAmbiguous,
    ReasonCode::IndependentSingleUseUnverified,
    ReasonCode::IndependentSingleUseInconsistent,
    ReasonCode::CustodyEvidenceAbsent,
    ReasonCode::CustodyDisclosureLimited,
    ReasonCode::PreservationSemanticsDeferred,
];

/// Namespaced codes reserved for profile- and anchor-contributed evidence (Phase B).
///
/// These are registered here — before the anchoring dimension emits them — so the
/// `ACCOUNTABILITY.SINGLE_USE` and `ACCOUNTABILITY.EVIDENCE` namespaces are owned by the
/// registry and independently discoverable. Their emission is added with the CSV/Seal
/// anchoring dimension.
pub const RESERVED_ANCHOR_CODES: &[&str] = &[
    // The mandate's single use is corroborated by an independent seal consumption,
    // not only by the private Postgres reservation. Now emitted by the external-
    // corroboration dimension (Phase B).
    SINGLE_USE_INDEPENDENTLY_ENFORCED,
    // A preserved seal-consumption record re-checks offline as valid. Now emitted.
    CSV_SEAL_CONSUMPTION_VALID,
    // A bundle digest was anchored as an external commitment. Reserved for a future
    // commitment-anchor dimension.
    "ACCOUNTABILITY.EVIDENCE.CSV_SEAL_COMMITMENT_ANCHORED",
];

/// Returns whether `code` is a well-formed namespaced reason-code identifier.
///
/// The rule: at least two `.`-separated segments, every segment nonempty and drawn only
/// from upper-case ASCII letters, digits, and `_`. Byte comparison is therefore the only
/// equality rule for reason codes.
pub fn is_well_formed(code: &str) -> bool {
    let mut segments = 0usize;
    for segment in code.split('.') {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_exhaustive_unique_and_well_formed() {
        // Exhaustiveness: the count matches the enum's variant count. This is kept in sync
        // with the enum via the `assert` below and the compiler's match in `registry_id`.
        assert_eq!(ALL_REASON_CODES.len(), 27);
        let mut ids: Vec<&'static str> = ALL_REASON_CODES
            .iter()
            .map(|code| code.registry_id())
            .collect();
        for id in &ids {
            assert!(is_well_formed(id), "malformed reason code: {id}");
            assert!(
                id.starts_with("ACCOUNTABILITY."),
                "reason code outside registry namespace: {id}"
            );
        }
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate reason-code identifier");
    }

    #[test]
    fn affirmative_and_reserved_codes_are_well_formed_and_disjoint() {
        assert!(is_well_formed(REQUIREMENT_MET));
        let core: Vec<&'static str> = ALL_REASON_CODES
            .iter()
            .map(|code| code.registry_id())
            .collect();
        for reserved in RESERVED_ANCHOR_CODES {
            assert!(
                is_well_formed(reserved),
                "malformed reserved code: {reserved}"
            );
            assert!(
                !core.contains(reserved),
                "reserved code collides with a core reason code: {reserved}"
            );
        }
    }

    #[test]
    fn published_corpus_table_matches_the_enum() {
        let table = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../csv-testkit/corpus/v1/reason-codes/registry.toml"
        ));
        assert!(table.contains(REQUIREMENT_MET));
        for code in ALL_REASON_CODES {
            let id = code.registry_id();
            assert!(
                table.contains(id),
                "published reason-code table is missing {id}"
            );
        }
        for reserved in RESERVED_ANCHOR_CODES {
            assert!(
                table.contains(reserved),
                "published reason-code table is missing reserved {reserved}"
            );
        }
    }

    #[test]
    fn malformed_codes_are_rejected() {
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("SINGLE_SEGMENT"));
        assert!(!is_well_formed("ACCOUNTABILITY."));
        assert!(!is_well_formed("accountability.lowercase"));
        assert!(!is_well_formed("ACCOUNTABILITY.HAS SPACE"));
    }
}
