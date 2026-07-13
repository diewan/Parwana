//! Application contract: the typed artifacts applications render.
//!
//! `csv-cli` is the reference presentation and `csv-wallet` is the graphical
//! one. Both consume *these* types — never each other's terminal output, and
//! never a hand-rolled projection of runtime internals. The contract covers:
//!
//! - [`receipt`] — mode-discriminated transfer receipts with permitted next actions
//! - [`event`] — transfer lifecycle events, including finality evidence
//! - [`recovery`] — the recovery actions a journaled transfer permits
//! - [`health`] — runtime health as reported by the runtime, not inferred
//! - [`intent`] — typed, expiring signing intents (opaque-byte signing is forbidden)
//!
//! # Versioning and fail-closed decoding
//!
//! Every artifact carries a [`ContractHeader`] binding the application-contract
//! schema version *and* the protocol version it was produced under. Decoding
//! goes through [`decode`], which rejects an unknown schema version, an
//! incompatible protocol major, a mismatched artifact kind, and any artifact
//! whose own [`ContractArtifact::validate`] fails. There is no lenient path: a
//! contract that cannot be fully understood is an error, never a partial value.
//!
//! # Not part of the contract
//!
//! Terminal formatting. Applications render these types however they wish;
//! the canonical CBOR encoding here is the interchange form, and the protocol
//! artifacts it carries (proof bundles, consignments) remain canonical.

pub mod event;
pub mod health;
pub mod intent;
pub mod receipt;
pub mod recovery;

use csv_codec::{CodecError, from_canonical_cbor, to_canonical_cbor};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub use event::{FinalityEvidence, TransferEvent, TransferPhase, VerificationAssuranceWire};
pub use health::{ComponentHealth, RuntimeHealthReport, RuntimeHealthState};
pub use intent::{IntentOperation, IntentValue, MAX_INTENT_TTL_SECS, SigningIntent};
pub use receipt::{
    AcceptBody, InvoiceBody, MaterializationWire, MaterializeBody, NextAction, ReceiptBody,
    SendBody, TransferMode, TransferReceipt, VerificationRecord,
};
pub use recovery::{RecoveryPlan, RecoveryReason};

/// Application-contract schema version.
///
/// Bumped whenever the shape of any artifact in this module changes. Consumers
/// reject any other value outright — see [`ContractHeader::validate`].
pub const APP_CONTRACT_SCHEMA_VERSION: u16 = 1;

/// Which artifact a [`ContractHeader`] introduces.
///
/// Carried in the header so a decoder can reject an artifact of the wrong kind
/// before interpreting its body, rather than relying on structural coincidence
/// between two artifacts that happen to share field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A [`TransferReceipt`].
    TransferReceipt,
    /// A [`TransferEvent`].
    TransferEvent,
    /// A [`RecoveryPlan`].
    RecoveryPlan,
    /// A [`RuntimeHealthReport`].
    RuntimeHealth,
    /// A [`SigningIntent`].
    SigningIntent,
}

/// Versioned header carried by every application-contract artifact.
///
/// `schema_version` discriminates the shape of this contract; `protocol_version`
/// records the protocol the artifact was produced under. Both are checked on
/// decode — an artifact from a future contract schema, or from an incompatible
/// protocol major, is rejected rather than interpreted optimistically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractHeader {
    /// Application-contract schema version. Must equal [`APP_CONTRACT_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Protocol version the producing runtime was running (e.g. `"1.0.0"`).
    pub protocol_version: String,
    /// The artifact this header introduces.
    pub artifact: ArtifactKind,
}

impl ContractHeader {
    /// Header for `artifact` at the current schema and protocol versions.
    pub fn current(artifact: ArtifactKind) -> Self {
        Self {
            schema_version: APP_CONTRACT_SCHEMA_VERSION,
            protocol_version: csv_protocol::version::PROTOCOL_VERSION.to_string(),
            artifact,
        }
    }

    /// Check this header against the current schema and the expected artifact kind.
    ///
    /// # Errors
    ///
    /// - [`ContractError::UnsupportedSchemaVersion`] if the schema version is not
    ///   exactly [`APP_CONTRACT_SCHEMA_VERSION`]. Both older and newer versions are
    ///   rejected: this crate makes no claim to understand either.
    /// - [`ContractError::IncompatibleProtocolVersion`] if the protocol major
    ///   differs from the running protocol's, or is unparseable.
    /// - [`ContractError::ArtifactMismatch`] if the header introduces a different
    ///   artifact than the caller is decoding.
    pub fn validate(&self, expected: ArtifactKind) -> Result<(), ContractError> {
        if self.schema_version != APP_CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: APP_CONTRACT_SCHEMA_VERSION,
            });
        }
        let found_major = protocol_major(&self.protocol_version)?;
        let running_major = protocol_major(csv_protocol::version::PROTOCOL_VERSION)?;
        if found_major != running_major {
            return Err(ContractError::IncompatibleProtocolVersion {
                found: self.protocol_version.clone(),
                running: csv_protocol::version::PROTOCOL_VERSION.to_string(),
            });
        }
        if self.artifact != expected {
            return Err(ContractError::ArtifactMismatch {
                expected,
                found: self.artifact,
            });
        }
        Ok(())
    }
}

/// Parse the major component of a `major.minor.patch` protocol version.
fn protocol_major(version: &str) -> Result<u32, ContractError> {
    let major = version
        .split('.')
        .next()
        .ok_or_else(|| ContractError::MalformedProtocolVersion(version.to_string()))?;
    major
        .parse::<u32>()
        .map_err(|_| ContractError::MalformedProtocolVersion(version.to_string()))
}

/// An artifact of the application contract.
///
/// Implementors are self-validating: [`validate`](ContractArtifact::validate)
/// enforces the artifact's own completeness invariants, and [`decode`] refuses
/// to hand back an artifact that fails them.
pub trait ContractArtifact: Serialize + DeserializeOwned {
    /// The kind this artifact's header must declare.
    const KIND: ArtifactKind;

    /// The artifact's header.
    fn header(&self) -> &ContractHeader;

    /// Enforce the artifact's completeness invariants.
    ///
    /// Called by [`decode`] after the header check, and directly by producers
    /// before an artifact is acted upon. Never returns a partial success.
    ///
    /// # Errors
    ///
    /// Returns a [`ContractError`] describing the first invariant violated.
    fn validate(&self) -> Result<(), ContractError>;
}

/// Encode an artifact as canonical CBOR.
///
/// The artifact is validated first: an incomplete artifact is never encoded, so
/// a peer cannot be handed something this side would itself reject.
///
/// # Errors
///
/// Returns a [`ContractError`] if the artifact fails validation or cannot be
/// canonically encoded.
pub fn encode<T: ContractArtifact>(artifact: &T) -> Result<Vec<u8>, ContractError> {
    artifact.header().validate(T::KIND)?;
    artifact.validate()?;
    Ok(to_canonical_cbor(artifact)?)
}

/// Decode an artifact from canonical CBOR, failing closed.
///
/// The version is read from a permissive probe *before* the strict decode, so an
/// artifact from an unknown schema version is reported as
/// [`ContractError::UnsupportedSchemaVersion`] rather than as an opaque codec
/// error. Either way it is an error — there is no path that yields a value from
/// bytes this crate does not fully understand.
///
/// # Errors
///
/// Returns a [`ContractError`] if the bytes are not canonical CBOR, if the header
/// is unknown/incompatible/mismatched, or if the artifact fails its own validation.
pub fn decode<T: ContractArtifact>(bytes: &[u8]) -> Result<T, ContractError> {
    /// Permissive view of any artifact: enough to read the header, ignoring the body.
    #[derive(Deserialize)]
    struct HeaderProbe {
        header: ContractHeader,
    }

    let probe: HeaderProbe = from_canonical_cbor(bytes)?;
    probe.header.validate(T::KIND)?;

    let artifact: T = from_canonical_cbor(bytes)?;
    artifact.header().validate(T::KIND)?;
    artifact.validate()?;
    Ok(artifact)
}

/// Errors raised when producing or consuming an application-contract artifact.
///
/// Every variant is a refusal. None of them is recoverable into a partial
/// artifact — a caller that sees one has no artifact at all.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    /// The artifact declares a contract schema version this build does not implement.
    #[error(
        "unsupported application-contract schema version {found} (this build implements {supported})"
    )]
    UnsupportedSchemaVersion {
        /// Version found in the artifact.
        found: u16,
        /// The only version this build accepts.
        supported: u16,
    },

    /// The artifact was produced under an incompatible protocol major version.
    #[error(
        "artifact protocol version {found} is incompatible with the running protocol {running}"
    )]
    IncompatibleProtocolVersion {
        /// Version found in the artifact.
        found: String,
        /// Version this build is running.
        running: String,
    },

    /// A protocol version string was not `major.minor.patch`.
    #[error("malformed protocol version: {0}")]
    MalformedProtocolVersion(String),

    /// The header introduces a different artifact than the one being decoded.
    #[error("artifact kind mismatch: expected {expected:?}, found {found:?}")]
    ArtifactMismatch {
        /// Kind the caller asked for.
        expected: ArtifactKind,
        /// Kind the artifact declares.
        found: ArtifactKind,
    },

    /// A field the artifact cannot be meaningful without is absent or empty.
    #[error("incomplete {artifact}: {field} is required")]
    MissingField {
        /// Artifact being validated.
        artifact: &'static str,
        /// The field that is missing or empty.
        field: &'static str,
    },

    /// A field carries a value that cannot describe a real observation.
    #[error("invalid {artifact}: {reason}")]
    InvalidField {
        /// Artifact being validated.
        artifact: &'static str,
        /// Why the value cannot be trusted.
        reason: String,
    },

    /// A signing intent's validity window has passed, or has not begun.
    #[error("signing intent is not valid at {now}: window is [{created_at}, {expires_at})")]
    IntentExpired {
        /// Time the check was made against (unix seconds).
        now: u64,
        /// Start of the intent's validity window (unix seconds).
        created_at: u64,
        /// End of the intent's validity window, exclusive (unix seconds).
        expires_at: u64,
    },

    /// Canonical encoding or decoding failed.
    #[error("canonical codec error: {0}")]
    Codec(#[from] CodecError),
}

/// Reject an empty string field.
pub(crate) fn require_nonempty(
    artifact: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::MissingField { artifact, field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::health::{RuntimeHealthReport, RuntimeHealthState};

    fn health() -> RuntimeHealthReport {
        RuntimeHealthReport::new(RuntimeHealthState::Healthy, vec![], 1_700_000_000)
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let report = health();
        let bytes = encode(&report).expect("valid artifact encodes");
        let back: RuntimeHealthReport = decode(&bytes).expect("its own encoding decodes");
        assert_eq!(back, report);
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let report = health();
        assert_eq!(encode(&report).unwrap(), encode(&report).unwrap());
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let mut report = health();
        report.header.schema_version = APP_CONTRACT_SCHEMA_VERSION + 1;
        // Encode past the producer-side guard to model bytes from a future peer.
        let bytes = to_canonical_cbor(&report).unwrap();

        let err =
            decode::<RuntimeHealthReport>(&bytes).expect_err("future schema must be rejected");
        assert!(matches!(
            err,
            ContractError::UnsupportedSchemaVersion { found, supported }
                if found == APP_CONTRACT_SCHEMA_VERSION + 1
                    && supported == APP_CONTRACT_SCHEMA_VERSION
        ));
    }

    #[test]
    fn older_schema_version_also_fails_closed() {
        let mut report = health();
        report.header.schema_version = 0;
        let bytes = to_canonical_cbor(&report).unwrap();
        assert!(matches!(
            decode::<RuntimeHealthReport>(&bytes),
            Err(ContractError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn incompatible_protocol_major_fails_closed() {
        let mut report = health();
        report.header.protocol_version = "2.0.0".to_string();
        let bytes = to_canonical_cbor(&report).unwrap();
        assert!(matches!(
            decode::<RuntimeHealthReport>(&bytes),
            Err(ContractError::IncompatibleProtocolVersion { .. })
        ));
    }

    #[test]
    fn malformed_protocol_version_fails_closed() {
        let mut report = health();
        report.header.protocol_version = "not-a-version".to_string();
        let bytes = to_canonical_cbor(&report).unwrap();
        assert!(matches!(
            decode::<RuntimeHealthReport>(&bytes),
            Err(ContractError::MalformedProtocolVersion(_))
        ));
    }

    #[test]
    fn artifact_kind_mismatch_fails_closed() {
        let mut report = health();
        report.header.artifact = ArtifactKind::SigningIntent;
        let bytes = to_canonical_cbor(&report).unwrap();
        assert!(matches!(
            decode::<RuntimeHealthReport>(&bytes),
            Err(ContractError::ArtifactMismatch { .. })
        ));
    }

    #[test]
    fn an_unknown_field_at_the_current_version_fails_closed() {
        // Same schema version, extra field: the peer is not speaking this contract.
        // Silently dropping the field would mean acting on a document we only
        // partly understood.
        #[derive(serde::Serialize)]
        struct Tampered {
            header: ContractHeader,
            state: RuntimeHealthState,
            components: Vec<health::ComponentHealth>,
            observed_at: u64,
            authorized: bool,
        }

        let bytes = to_canonical_cbor(&Tampered {
            header: ContractHeader::current(ArtifactKind::RuntimeHealth),
            state: RuntimeHealthState::Healthy,
            components: vec![],
            observed_at: 1_700_000_000,
            authorized: true,
        })
        .unwrap();

        assert!(
            decode::<RuntimeHealthReport>(&bytes).is_err(),
            "an artifact carrying a field this build does not know must be refused"
        );
    }

    #[test]
    fn truncated_bytes_fail_closed() {
        let bytes = encode(&health()).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(decode::<RuntimeHealthReport>(truncated).is_err());
    }

    #[test]
    fn compatible_protocol_minor_is_accepted() {
        // Only the major gates compatibility; a minor/patch bump still decodes.
        let mut report = health();
        report.header.protocol_version = "1.9.3".to_string();
        let bytes = to_canonical_cbor(&report).unwrap();
        assert!(decode::<RuntimeHealthReport>(&bytes).is_ok());
    }
}
