//! The published V2 protocol reason-code registry.
//!
//! Every stable identifier the V2 protocol path can emit is enumerated here,
//! aggregated from the crate that owns each vocabulary. This module is the
//! single place a consumer — or the portable conformance package — may draw a
//! reason code from.
//!
//! The registry exists because a package that tells a consumer to expect
//! `PROTOCOL.DAG.CYCLE` has made a promise, and nothing previously checked that
//! the protocol could keep it. [`registry`] is derived from the implementation's
//! own `registry_id` functions, so a code cannot appear here without a code path
//! that emits it, and [`contains`] is what the conformance gate calls.
//!
//! This is the V2 protocol registry. The V1 accountability verifier publishes
//! its own, disjoint `ACCOUNTABILITY.*` registry in
//! `csv_accountability_verify::reason_codes`.

use csv_hash::dag::DagStructureError;
use csv_protocol::exclusivity::ExclusivityError;
use csv_protocol::reference::ReferenceDecodeError;
use csv_protocol::resolution::ResolutionError;
use csv_runtime::send_transfer::SendCompletion;
use csv_runtime::{AcceptanceErrorCode, AcceptanceResult};
use csv_storage::CheckpointObservationCode;
use csv_verifier::ProtocolReasonCode;
use csv_wire::{ConsignmentV2ErrorCode, LegacyConsignmentErrorCode, LegacyIntegrityDimensions};

/// Version of the published registry projection.
///
/// Bumped whenever a code is added, removed, or renamed. A consumer that pins
/// this value is pinning the vocabulary it knows how to route on.
pub const REGISTRY_VERSION: u32 = 1;

/// One vocabulary within the registry.
///
/// A family is owned by exactly one crate, so a code's provenance is never
/// ambiguous and two crates cannot mint the same identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReasonCodeFamily {
    /// Stable family name.
    pub name: &'static str,
    /// The crate whose code paths emit this family.
    pub emitted_by: &'static str,
    /// Identifier prefix every member of this family carries.
    pub prefix: &'static str,
}

/// One published reason code and the family that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReasonCodeEntry {
    /// Stable registry identifier.
    pub code: &'static str,
    /// Family that owns it.
    pub family: ReasonCodeFamily,
}

const DIMENSION_ASSURANCE: ReasonCodeFamily = ReasonCodeFamily {
    name: "dimension-assurance",
    emitted_by: "csv-verifier",
    prefix: "PROTOCOL.",
};
const DAG_STRUCTURE: ReasonCodeFamily = ReasonCodeFamily {
    name: "dag-structure",
    emitted_by: "csv-hash",
    prefix: "PROTOCOL.DAG.",
};
const REFERENCE_DECODE: ReasonCodeFamily = ReasonCodeFamily {
    name: "reference-decode",
    emitted_by: "csv-protocol",
    prefix: "PROTOCOL.REFERENCE.",
};
const STATE_USE: ReasonCodeFamily = ReasonCodeFamily {
    name: "state-use",
    emitted_by: "csv-protocol",
    prefix: "PROTOCOL.EXCLUSIVITY.",
};
const RESOLUTION: ReasonCodeFamily = ReasonCodeFamily {
    name: "resolution",
    emitted_by: "csv-protocol",
    prefix: "PROTOCOL.RESOLUTION.",
};
const WIRE_V2: ReasonCodeFamily = ReasonCodeFamily {
    name: "wire-v2",
    emitted_by: "csv-wire",
    prefix: "WIRE.V2.",
};
const WIRE_V1: ReasonCodeFamily = ReasonCodeFamily {
    name: "wire-v1-legacy-inspection",
    emitted_by: "csv-wire",
    prefix: "WIRE.V1.",
};
const ACCEPTANCE: ReasonCodeFamily = ReasonCodeFamily {
    name: "recipient-acceptance",
    emitted_by: "csv-runtime",
    prefix: "ACCEPT.V2.",
};
const SEND_LIFECYCLE: ReasonCodeFamily = ReasonCodeFamily {
    name: "send-lifecycle",
    emitted_by: "csv-runtime",
    prefix: "RUNTIME.SEND.",
};
const ACCEPTED_STATE: ReasonCodeFamily = ReasonCodeFamily {
    name: "accepted-state-lifecycle",
    emitted_by: "csv-storage",
    prefix: "STORAGE.",
};

/// Every family in the registry, in stable published order.
pub const FAMILIES: &[ReasonCodeFamily] = &[
    DIMENSION_ASSURANCE,
    DAG_STRUCTURE,
    REFERENCE_DECODE,
    STATE_USE,
    RESOLUTION,
    WIRE_V2,
    WIRE_V1,
    ACCEPTANCE,
    SEND_LIFECYCLE,
    ACCEPTED_STATE,
];

/// The complete published registry, in stable family-then-declaration order.
///
/// Built from each owning crate's own identifier functions. There is no literal
/// code string in this function: a code reaches the registry only by being
/// something an implementation emits.
pub fn registry() -> Vec<ReasonCodeEntry> {
    let mut entries = Vec::new();
    let mut push = |family: ReasonCodeFamily, code: &'static str| {
        entries.push(ReasonCodeEntry { code, family });
    };

    for code in ProtocolReasonCode::ALL {
        push(DIMENSION_ASSURANCE, code.registry_id());
    }
    for code in DagStructureError::ALL_REGISTRY_IDS {
        push(DAG_STRUCTURE, code);
    }
    for code in ReferenceDecodeError::ALL_REGISTRY_IDS {
        push(REFERENCE_DECODE, code);
    }
    for code in ExclusivityError::ALL_REGISTRY_IDS {
        push(STATE_USE, code);
    }
    for code in ResolutionError::ALL_REGISTRY_IDS {
        push(RESOLUTION, code);
    }
    for code in ConsignmentV2ErrorCode::ALL {
        push(WIRE_V2, code.registry_id());
    }
    for code in LegacyConsignmentErrorCode::ALL {
        push(WIRE_V1, code.registry_id());
    }
    for code in LegacyIntegrityDimensions::ALL_REGISTRY_IDS {
        push(WIRE_V1, code);
    }
    push(ACCEPTANCE, AcceptanceResult::REGISTRY_ID);
    for code in AcceptanceErrorCode::ALL {
        push(ACCEPTANCE, code.registry_id());
    }
    for code in SendCompletion::ALL {
        push(SEND_LIFECYCLE, code.registry_id());
    }
    for code in CheckpointObservationCode::ALL {
        push(ACCEPTED_STATE, code.registry_id());
    }
    entries
}

/// Whether `code` is a published V2 protocol reason code.
///
/// This is the membership test the conformance gate uses. A package case whose
/// expected reason code fails it is declaring an expectation nothing can meet.
pub fn contains(code: &str) -> bool {
    registry().iter().any(|entry| entry.code == code)
}

/// Whether an identifier is a well-formed reason code.
///
/// Two or more dot-separated segments of uppercase ASCII, digits, and
/// underscores. Mirrors the rule the V1 accountability registry enforces, so
/// the two registries stay mutually legible.
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

/// Render the registry as the published TOML projection.
///
/// This is what the designated generator writes to
/// `conformance/v2-reason-code-registry.toml`; the same bytes are pinned by
/// digest in the release declaration.
pub fn render_published_registry() -> String {
    let mut out = String::new();
    out.push_str(
        "# Published V2 protocol reason-code registry.\n\
         #\n\
         # Generated by `cargo run -p csv-sdk --example generate_portable_conformance`.\n\
         # Never hand-edited. Each identifier is produced by the owning crate's own\n\
         # `registry_id` function, so this file cannot name a code no code path emits.\n\
         #\n\
         # The portable conformance package may only declare expected reason codes\n\
         # that appear here; a mechanical gate enforces that in both directions.\n\
         #\n\
         # Disjoint from the V1 `ACCOUNTABILITY.*` registry published at\n\
         # csv-testkit/corpus/v1/reason-codes/registry.toml.\n\n",
    );
    out.push_str(&format!("registry_version = {REGISTRY_VERSION}\n"));
    out.push_str("wire_version = 2\n\n");
    for family in FAMILIES {
        out.push_str("[[family]]\n");
        out.push_str(&format!("name = \"{}\"\n", family.name));
        out.push_str(&format!("emitted_by = \"{}\"\n", family.emitted_by));
        out.push_str(&format!("prefix = \"{}\"\n", family.prefix));
        let codes: Vec<&'static str> = registry()
            .iter()
            .filter(|entry| entry.family == *family)
            .map(|entry| entry.code)
            .collect();
        out.push_str("codes = [\n");
        for code in codes {
            out.push_str(&format!("  \"{code}\",\n"));
        }
        out.push_str("]\n\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_code_is_well_formed_and_in_its_family_namespace() {
        for entry in registry() {
            assert!(
                is_well_formed(entry.code),
                "malformed reason code: {}",
                entry.code
            );
            assert!(
                entry.code.starts_with(entry.family.prefix),
                "{} is published under family {} but does not carry its prefix",
                entry.code,
                entry.family.name
            );
        }
    }

    /// Two crates minting the same identifier would make a consumer's routing
    /// decision depend on which layer answered first.
    #[test]
    fn no_two_families_publish_the_same_identifier() {
        let mut codes: Vec<&'static str> = registry().iter().map(|entry| entry.code).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "two families publish one identifier");
    }

    /// The V2 protocol registry and the V1 accountability registry are separate
    /// vocabularies; an overlap would make a code's meaning depend on which
    /// verifier a consumer happened to be holding.
    #[test]
    fn the_v2_registry_is_disjoint_from_the_v1_accountability_registry() {
        for entry in registry() {
            assert!(
                !entry.code.starts_with("ACCOUNTABILITY."),
                "{} belongs to the V1 registry's namespace",
                entry.code
            );
        }
    }

    #[test]
    fn membership_is_exact() {
        assert!(contains("PROTOCOL.DAG.CYCLE"));
        assert!(contains("ACCEPT.V2.ACCEPTED"));
        assert!(contains("STORAGE.CHECKPOINT.ORPHANED"));
        assert!(contains("RUNTIME.SEND.RECOVERED"));
        assert!(contains("WIRE.V1.PORTABLE_NON_EQUIVOCATION_UNAVAILABLE"));
        // Codes the package declared before this registry existed, which no
        // code path ever emitted.
        assert!(!contains("PROTOCOL.DAG.DUPLICATE_NODE"));
        assert!(!contains("PROTOCOL.STATE.COMMITMENT_MISMATCH"));
        assert!(!contains("PROTOCOL.STATE.OUTPUT_NOT_FOUND"));
        assert!(!contains("PROTOCOL.TRANSITION.COMMITMENT_MISMATCH"));
        assert!(!contains(""));
    }

    #[test]
    fn malformed_identifiers_are_rejected() {
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("SINGLE_SEGMENT"));
        assert!(!is_well_formed("PROTOCOL."));
        assert!(!is_well_formed("protocol.lowercase"));
        assert!(!is_well_formed("PROTOCOL.HAS SPACE"));
    }
}
