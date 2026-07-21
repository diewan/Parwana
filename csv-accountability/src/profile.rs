//! Registerable action-profile descriptors and the open profile-codec boundary.
//!
//! An action profile gives provider-specific meaning to a generic [`crate::ActionIntent`].
//! Profiles are *registered data plus an open codec*, not sealed protocol types: the
//! canonical meaning still lives in versioned Parwana rules (a [`ProfileDescriptor`] and a
//! [`ProfileCodec`]), but any crate may implement a new profile and register it without
//! editing the accountability core (Master Plan §5.10, §36).

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::intent::IntentError;

/// Maximum UTF-8 byte length of a stable profile or evidence-source identifier.
pub const MAX_PROFILE_ID_BYTES: usize = 128;

/// Returns whether `value` is a well-formed stable identifier.
///
/// Stable identifiers are nonempty, within [`MAX_PROFILE_ID_BYTES`], and use only
/// lower-case ASCII letters, digits, `.`, and `-`. They never contain whitespace or
/// upper-case characters so that byte comparison is the only equality rule.
fn is_stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

/// Stable, namespaced identifier of a registered action profile.
///
/// For example `org.diewan.accountability.github-deployment.intent.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileId(String);

impl ProfileId {
    /// Validates and constructs a stable profile identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IntentError> {
        let value = value.into();
        if is_stable_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(IntentError::InvalidProfileId)
        }
    }

    /// Returns the stable identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identifier of a specific evidence source expected by a profile.
///
/// For example `evidence.github.deployment-record`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceSourceId(String);

impl EvidenceSourceId {
    /// Validates and constructs a stable evidence-source identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IntentError> {
        let value = value.into();
        if is_stable_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(IntentError::InvalidProfileId)
        }
    }

    /// Returns the stable identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independence class of an evidence source relative to the executor and the target
/// provider.
///
/// The class fixes how much weight a source may lend to an assurance dimension:
/// `Executor` claims originate with the reporting executor itself; `ProviderCorroborating`
/// is external to the executor but may share trust with the target provider;
/// `ExternalAnchor` is external to *both* (for example an independent single-use seal),
/// and is therefore the strongest corroboration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceSourceClass {
    /// The claim originates with the executor itself.
    Executor,
    /// External to the executor; may share trust with the target provider.
    ProviderCorroborating,
    /// External to both the executor and the target provider.
    ExternalAnchor,
}

impl EvidenceSourceClass {
    /// Returns whether this class corroborates the executor's own report.
    pub const fn is_corroborating(self) -> bool {
        matches!(self, Self::ProviderCorroborating | Self::ExternalAnchor)
    }
}

/// One evidence source declared by a profile, with its independence class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSourceDecl {
    /// Stable evidence-source identifier.
    pub id: EvidenceSourceId,
    /// Independence class relative to executor and provider.
    pub class: EvidenceSourceClass,
}

impl EvidenceSourceDecl {
    /// Constructs an evidence-source declaration.
    pub fn new(id: EvidenceSourceId, class: EvidenceSourceClass) -> Self {
        Self { id, class }
    }
}

/// Registered rule for whether a quarantined mandate may ever be released.
///
/// This is the data form of [`crate::state::QuarantineReleasePolicy`] that a descriptor
/// carries, so the "no sufficient absence predicate" law for a provider is a registered
/// property rather than a hard-coded constructor at the call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineReleaseRule {
    /// The profile has no sufficient absence predicate; release is unreachable.
    NeverReleasable,
    /// A registered policy defines evidence sufficient to prove non-acceptance.
    ProfileDefined {
        /// Stable policy identifier.
        policy_id: String,
        /// Commitment to the exact policy parameters.
        policy_digest: [u8; 32],
    },
}

/// Versioned, registered description of an action profile.
///
/// The descriptor is the *data* half of a registry entry: the stable identity, the
/// generic-field bindings ([`Self::action_type`], [`Self::parameters_media_type`], and the
/// domain tag used for the parameters commitment), the complete evidence-source
/// inventory, the quarantine-release law, and size limits. The behavioural half is a
/// [`ProfileCodec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDescriptor {
    /// Stable, namespaced profile identifier.
    pub profile_id: ProfileId,
    /// Stable action type bound into the generic intent.
    pub action_type: String,
    /// Registered media type of the canonical parameter commitment.
    pub parameters_media_type: String,
    /// Domain separator hashed with the profile bytes to form the parameters commitment.
    pub parameters_domain_tag: Vec<u8>,
    /// Complete evidence-source inventory for this profile version.
    pub evidence_sources: Vec<EvidenceSourceDecl>,
    /// Registered rule governing release of a quarantined mandate.
    pub quarantine_release: QuarantineReleaseRule,
    /// Maximum number of context commitments accepted on an intent.
    pub max_context_commitments: usize,
    /// Maximum byte length of a requester identity reference.
    pub max_identity_bytes: usize,
}

impl ProfileDescriptor {
    /// Validates the descriptor's evidence-source declaration.
    ///
    /// The inventory must be nonempty, have unique identifiers, and contain at least one
    /// executor-class source and at least one corroborating source. Because each source
    /// carries exactly one class, the earlier "complete and disjoint" requirement is
    /// satisfied by construction.
    pub fn validate(&self) -> Result<(), IntentError> {
        let sources = &self.evidence_sources;
        if sources.is_empty() {
            return Err(IntentError::InvalidEvidenceSourceDeclaration);
        }
        let has_duplicate = sources
            .iter()
            .enumerate()
            .any(|(index, decl)| sources[index + 1..].iter().any(|other| other.id == decl.id));
        let has_executor = sources
            .iter()
            .any(|decl| matches!(decl.class, EvidenceSourceClass::Executor));
        let has_corroborating = sources.iter().any(|decl| decl.class.is_corroborating());
        if has_duplicate || !has_executor || !has_corroborating {
            return Err(IntentError::InvalidEvidenceSourceDeclaration);
        }
        Ok(())
    }

    /// Returns the corresponding pure-protocol quarantine-release policy.
    pub fn quarantine_release_policy(&self) -> crate::state::QuarantineReleasePolicy {
        match &self.quarantine_release {
            QuarantineReleaseRule::NeverReleasable => crate::state::QuarantineReleasePolicy::Never,
            QuarantineReleaseRule::ProfileDefined {
                policy_id,
                policy_digest,
            } => crate::state::QuarantineReleasePolicy::ProfileDefined {
                policy_id: policy_id.clone(),
                policy_digest: *policy_digest,
            },
        }
    }
}

/// The open, behavioural half of a registered profile.
///
/// A codec decodes and validates a profile encoded as canonical bytes and derives its
/// stable target. It is object-safe so a [`crate::registry::ProfileRegistry`] can hold
/// `Box<dyn ProfileCodec>`. Implementing this trait plus supplying a [`ProfileDescriptor`]
/// is all that is required to register a new profile — no accountability-core edit.
pub trait ProfileCodec {
    /// The stable descriptor bound to this codec.
    fn descriptor(&self) -> &ProfileDescriptor;

    /// Decodes and validates `profile_bytes` as this profile's canonical encoding.
    ///
    /// On success returns the profile's stable target bytes. Implementations MUST reject
    /// any input that is not the exact canonical byte encoding of a valid profile value
    /// (non-canonical or trailing bytes fail closed), so that verification is
    /// independently reproducible from the bytes alone (§5.7).
    fn validate_canonical_bytes(&self, profile_bytes: &[u8]) -> Result<Vec<u8>, IntentError>;
}

/// A boxed, registerable profile codec.
pub type BoxedProfileCodec = Box<dyn ProfileCodec + Send + Sync>;
