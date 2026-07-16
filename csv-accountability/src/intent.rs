//! Canonical action-intent and profile-envelope semantics.

use alloc::{string::String, vec::Vec};

use csv_codec::ManualEncoder;
use csv_hash::{ActionIntentDomain, DomainSeparatedHash, GateProfileDomain};

use crate::id::{ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION};
use crate::{GateProfileId, IntentId, ObjectVersion, ProtocolVersion};

/// Maximum UTF-8 byte length of any presentation label.
pub const MAX_DISPLAY_BYTES: usize = 255;
/// Maximum number of context commitments on an intent.
pub const MAX_CONTEXT_COMMITMENTS: usize = 32;
/// Maximum number of administrator-controlled required contexts.
pub const MAX_REQUIRED_CONTEXTS: usize = 32;
/// Maximum byte length of a stable requester identity reference.
pub const MAX_IDENTITY_BYTES: usize = 4_096;
/// Fixed task used by the first production deployment profile.
pub const GITHUB_DEPLOYMENT_TASK_V1: &str = "deploy";
/// Media type of the canonical parameter commitment.
pub const PARAMETERS_MEDIA_TYPE_V1: &str = "application/vnd.diewan.github-deployment-v1+csv-binary";

/// A validation failure for an action intent or profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentError {
    /// A required string was empty.
    EmptyField(&'static str),
    /// A presentation string exceeded its protocol limit.
    DisplayFieldTooLong(&'static str),
    /// The commit reference was not one full, lower-case hexadecimal SHA-1.
    InvalidCommitSha,
    /// The generic target did not match the profile's stable provider target.
    TargetMismatch,
    /// The parameter commitment did not bind the supplied profile.
    ParametersCommitmentMismatch,
    /// The first profile permits only its fixed task.
    UnsupportedTask,
    /// Automatic merge is forbidden by the first profile.
    AutoMergeForbidden,
    /// Production and transient flags would weaken the first profile.
    InvalidEnvironmentClassification,
    /// Explicit required contexts must be nonempty, sorted, and unique.
    InvalidRequiredContexts,
    /// Too many context commitments were supplied.
    TooManyContextCommitments,
    /// The object version is not supported by this implementation.
    UnsupportedVersion,
    /// A stable provider identifier used a reserved zero value.
    InvalidStableId,
    /// The requester identity exceeded its protocol size limit.
    IdentityTooLong,
    /// Required contexts did not match the administrator gate-policy digest.
    GatePolicyMismatch,
    /// A profile omitted, overlapped, or otherwise blurred its evidence-source classes.
    InvalidEvidenceSourceDeclaration,
}

/// A registered evidence source expected by an action profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileEvidenceSource {
    /// The executor's own execution-attempt record.
    ExecutorAttemptRecord,
    /// GitHub's accepted Deployments API object and status records.
    GitHubDeploymentRecord,
    /// A correlated GitHub webhook delivery retained with authenticity material.
    GitHubWebhookDelivery,
    /// Environment-protection configuration obtained from an authenticated GitHub API response.
    GitHubAuthenticatedEnvironmentConfiguration,
}

mod profile_sealed {
    use super::IntentError;

    pub trait Sealed {
        fn validate_fields(&self) -> Result<(), IntentError>;
    }
}

/// Validation contract implemented by every versioned action profile.
///
/// The two source sets are mandatory and disjoint. Corroborating means evidence
/// external to the reporting executor; it does not by itself claim that the
/// source is independent of the target provider or that its assertions are true.
pub trait ProfileValidator: profile_sealed::Sealed {
    /// Complete source inventory for this profile version; omission is invalid.
    const EXPECTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource];
    /// Sources that corroborate the executor's report.
    const CORROBORATING_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource];
    /// Sources whose claims originate with the executor itself.
    const SELF_REPORTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource];
}

/// Validates a profile's fields and its complete, disjoint evidence-source declaration.
pub fn validate_profile<P: ProfileValidator>(profile: &P) -> Result<(), IntentError> {
    validate_evidence_source_declaration::<P>()?;
    profile_sealed::Sealed::validate_fields(profile)
}

const GITHUB_CORROBORATING_EVIDENCE: &[ProfileEvidenceSource] = &[
    ProfileEvidenceSource::GitHubDeploymentRecord,
    ProfileEvidenceSource::GitHubWebhookDelivery,
    ProfileEvidenceSource::GitHubAuthenticatedEnvironmentConfiguration,
];
const GITHUB_SELF_REPORTED_EVIDENCE: &[ProfileEvidenceSource] =
    &[ProfileEvidenceSource::ExecutorAttemptRecord];
const GITHUB_EXPECTED_EVIDENCE: &[ProfileEvidenceSource] = &[
    ProfileEvidenceSource::ExecutorAttemptRecord,
    ProfileEvidenceSource::GitHubDeploymentRecord,
    ProfileEvidenceSource::GitHubWebhookDelivery,
    ProfileEvidenceSource::GitHubAuthenticatedEnvironmentConfiguration,
];

/// How GitHub commit-status contexts are applied to a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequiredContexts {
    /// Omit `required_contexts`, requiring all submitted contexts per GitHub's API semantics.
    AllSubmitted,
    /// Use this administrator-controlled, sorted, nonempty set.
    ExplicitNonEmpty(Vec<String>),
}

impl RequiredContexts {
    /// Validates and constructs an explicit administrator-controlled context set.
    pub fn explicit(contexts: Vec<String>) -> Result<Self, IntentError> {
        if contexts.is_empty()
            || contexts.len() > MAX_REQUIRED_CONTEXTS
            || contexts.iter().any(|value| {
                value.is_empty()
                    || value.trim() != value
                    || value.len() > MAX_DISPLAY_BYTES
                    || value.chars().any(char::is_control)
            })
            || contexts.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(IntentError::InvalidRequiredContexts);
        }
        Ok(Self::ExplicitNonEmpty(contexts))
    }

    /// Derives the gate-policy identifier that commits to this exact mode and context set.
    pub fn gate_policy_id(&self) -> Result<GateProfileId, IntentError> {
        if let Self::ExplicitNonEmpty(contexts) = self {
            Self::explicit(contexts.clone())?;
        }
        let mut bytes = Vec::new();
        match self {
            Self::AllSubmitted => bytes.push(0),
            Self::ExplicitNonEmpty(contexts) => {
                bytes.push(1);
                push_u32(&mut bytes, contexts.len() as u32);
                for context in contexts {
                    push_string(&mut bytes, context);
                }
            }
        }
        Ok(GateProfileId::from_digest(
            DomainSeparatedHash::<GateProfileDomain>::hash_multiple([
                b"required-contexts-v1".as_slice(),
                bytes.as_slice(),
            ])
            .into_inner(),
        ))
    }
}

/// Exact, constrained GitHub Deployments API profile for the first production slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubDeploymentIntentV1 {
    /// Stable provider repository identifier; names never replace it.
    pub repository_id: u64,
    /// Presentation-only repository owner.
    pub repository_owner: String,
    /// Presentation-only repository name.
    pub repository_name: String,
    /// Approved full lower-case commit SHA.
    pub commit_sha: String,
    /// Exact Deployments API `ref`, required to equal `commit_sha`.
    pub exact_ref: String,
    /// Stable provider environment identifier.
    pub environment_id: u64,
    /// Presentation-only environment name.
    pub environment_name: String,
    /// Commit-status gate selection.
    pub required_contexts: RequiredContexts,
    /// Commitment to the canonical correlation payload constructed outside the agent.
    pub payload_commitment: [u8; 32],
    /// Optional artifact digest known before dispatch.
    pub artifact_digest: Option<[u8; 32]>,
    /// Administrator-controlled gate-policy digest.
    pub deployment_gate_policy_digest: GateProfileId,
}

impl GitHubDeploymentIntentV1 {
    /// Validates all fixed and constrained fields of the production profile.
    pub fn validate(&self) -> Result<(), IntentError> {
        validate_profile(self)
    }

    fn validate_profile_fields(&self) -> Result<(), IntentError> {
        if self.repository_id == 0 || self.environment_id == 0 {
            return Err(IntentError::InvalidStableId);
        }
        for (field, value) in [
            ("repository_owner", self.repository_owner.as_str()),
            ("repository_name", self.repository_name.as_str()),
            ("environment_name", self.environment_name.as_str()),
        ] {
            if value.is_empty() {
                return Err(IntentError::EmptyField(field));
            }
            if value.len() > MAX_DISPLAY_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(IntentError::DisplayFieldTooLong(field));
            }
        }
        if !is_full_lower_hex_sha(&self.commit_sha) || self.exact_ref != self.commit_sha {
            return Err(IntentError::InvalidCommitSha);
        }
        if let RequiredContexts::ExplicitNonEmpty(contexts) = &self.required_contexts {
            RequiredContexts::explicit(contexts.clone())?;
        }
        if self.deployment_gate_policy_digest != self.required_contexts.gate_policy_id()? {
            return Err(IntentError::GatePolicyMismatch);
        }
        Ok(())
    }

    /// The immutable Deployments API task for this profile.
    pub const fn task(&self) -> &'static str {
        GITHUB_DEPLOYMENT_TASK_V1
    }

    /// Automatic merge is fixed off and cannot be supplied by an agent.
    pub const fn auto_merge(&self) -> bool {
        false
    }

    /// The first slice is always classified as production.
    pub const fn production_environment(&self) -> bool {
        true
    }

    /// The first slice never creates a transient environment.
    pub const fn transient_environment(&self) -> bool {
        false
    }

    /// Stable target bytes, independent of presentation names.
    pub fn stable_target(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&self.repository_id.to_be_bytes());
        bytes.extend_from_slice(&self.environment_id.to_be_bytes());
        bytes
    }

    /// Canonical profile bytes used by the generic intent commitment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, ACCOUNTABILITY_OBJECT_VERSION.get());
        push_u64(&mut out, self.repository_id);
        push_string(&mut out, &self.repository_owner);
        push_string(&mut out, &self.repository_name);
        push_string(&mut out, &self.commit_sha);
        push_string(&mut out, &self.exact_ref);
        push_string(&mut out, GITHUB_DEPLOYMENT_TASK_V1);
        push_u64(&mut out, self.environment_id);
        push_string(&mut out, &self.environment_name);
        match &self.required_contexts {
            RequiredContexts::AllSubmitted => out.push(0),
            RequiredContexts::ExplicitNonEmpty(contexts) => {
                out.push(1);
                push_u32(&mut out, contexts.len() as u32);
                for context in contexts {
                    push_string(&mut out, context);
                }
            }
        }
        out.push(0); // auto_merge=false
        out.extend_from_slice(&self.payload_commitment);
        out.push(1); // production_environment=true
        out.push(0); // transient_environment=false
        push_option_digest(&mut out, self.artifact_digest);
        out.extend_from_slice(self.deployment_gate_policy_digest.as_bytes());
        Ok(out)
    }
}

impl ProfileValidator for GitHubDeploymentIntentV1 {
    const EXPECTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] = GITHUB_EXPECTED_EVIDENCE;
    const CORROBORATING_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
        GITHUB_CORROBORATING_EVIDENCE;
    const SELF_REPORTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
        GITHUB_SELF_REPORTED_EVIDENCE;
}

impl profile_sealed::Sealed for GitHubDeploymentIntentV1 {
    fn validate_fields(&self) -> Result<(), IntentError> {
        self.validate_profile_fields()
    }
}

fn validate_evidence_source_declaration<P: ProfileValidator>() -> Result<(), IntentError> {
    let corroborating = P::CORROBORATING_EVIDENCE_SOURCES;
    let self_reported = P::SELF_REPORTED_EVIDENCE_SOURCES;
    let expected = P::EXPECTED_EVIDENCE_SOURCES;
    if corroborating.is_empty()
        || self_reported.is_empty()
        || expected.is_empty()
        || corroborating
            .iter()
            .any(|source| self_reported.contains(source))
        || has_duplicate_sources(corroborating)
        || has_duplicate_sources(self_reported)
        || has_duplicate_sources(expected)
        || expected
            .iter()
            .any(|source| !corroborating.contains(source) && !self_reported.contains(source))
        || corroborating
            .iter()
            .chain(self_reported.iter())
            .any(|source| !expected.contains(source))
    {
        return Err(IntentError::InvalidEvidenceSourceDeclaration);
    }
    Ok(())
}

fn has_duplicate_sources(sources: &[ProfileEvidenceSource]) -> bool {
    sources
        .iter()
        .enumerate()
        .any(|(index, source)| sources[index + 1..].contains(source))
}

/// Exact generic action proposal bound to a versioned provider profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionIntent {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of the generic intent.
    pub intent_version: ObjectVersion,
    /// Stable profile identifier.
    pub profile_id: GateProfileId,
    /// Stable action type.
    pub action_type: String,
    /// Stable provider target bytes.
    pub target: Vec<u8>,
    /// Commitment to canonical profile parameters.
    pub parameters_commitment: [u8; 32],
    /// Registered parameter media type.
    pub parameters_media_type: String,
    /// Stable requester identity bytes.
    pub requested_by: Vec<u8>,
    /// Unix timestamp in seconds.
    pub requested_at: u64,
    /// Caller-generated anti-replay nonce.
    pub request_nonce: [u8; 32],
    /// Ordered context commitments.
    pub context_commitments: Vec<[u8; 32]>,
    /// The exact provider profile envelope.
    pub profile: GitHubDeploymentIntentV1,
}

impl ActionIntent {
    /// Constructs a validated GitHub deployment action intent.
    pub fn github_deployment(
        profile_id: GateProfileId,
        requested_by: Vec<u8>,
        requested_at: u64,
        request_nonce: [u8; 32],
        context_commitments: Vec<[u8; 32]>,
        profile: GitHubDeploymentIntentV1,
    ) -> Result<Self, IntentError> {
        profile.validate()?;
        if requested_by.is_empty() {
            return Err(IntentError::EmptyField("requested_by"));
        }
        if requested_by.len() > MAX_IDENTITY_BYTES {
            return Err(IntentError::IdentityTooLong);
        }
        if context_commitments.len() > MAX_CONTEXT_COMMITMENTS {
            return Err(IntentError::TooManyContextCommitments);
        }
        let profile_bytes = profile.canonical_bytes()?;
        let commitment = DomainSeparatedHash::<GateProfileDomain>::hash_multiple([
            b"github-deployment-parameters-v1".as_slice(),
            profile_bytes.as_slice(),
        ])
        .into_inner();
        Ok(Self {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            intent_version: ACCOUNTABILITY_OBJECT_VERSION,
            profile_id,
            action_type: String::from("github.deployment"),
            target: profile.stable_target(),
            parameters_commitment: commitment,
            parameters_media_type: String::from(PARAMETERS_MEDIA_TYPE_V1),
            requested_by,
            requested_at,
            request_nonce,
            context_commitments,
            profile,
        })
    }

    /// Validates bindings between generic fields and the provider profile.
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION {
            return Err(IntentError::UnsupportedVersion);
        }
        if self.intent_version != ACCOUNTABILITY_OBJECT_VERSION {
            return Err(IntentError::UnsupportedVersion);
        }
        self.profile.validate()?;
        if self.action_type != "github.deployment" {
            return Err(IntentError::UnsupportedTask);
        }
        if self.target != self.profile.stable_target() {
            return Err(IntentError::TargetMismatch);
        }
        let profile_bytes = self.profile.canonical_bytes()?;
        let expected = DomainSeparatedHash::<GateProfileDomain>::hash_multiple([
            b"github-deployment-parameters-v1".as_slice(),
            profile_bytes.as_slice(),
        ])
        .into_inner();
        if self.parameters_commitment != expected
            || self.parameters_media_type != PARAMETERS_MEDIA_TYPE_V1
        {
            return Err(IntentError::ParametersCommitmentMismatch);
        }
        if self.requested_by.is_empty() {
            return Err(IntentError::EmptyField("requested_by"));
        }
        if self.requested_by.len() > MAX_IDENTITY_BYTES {
            return Err(IntentError::IdentityTooLong);
        }
        if self.context_commitments.len() > MAX_CONTEXT_COMMITMENTS {
            return Err(IntentError::TooManyContextCommitments);
        }
        Ok(())
    }

    /// Returns canonical bytes for hashing and independent verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u16(&mut out, self.intent_version.get());
        out.extend_from_slice(self.profile_id.as_bytes());
        push_string(&mut out, &self.action_type);
        push_bytes(&mut out, &self.target);
        out.extend_from_slice(&self.parameters_commitment);
        push_string(&mut out, &self.parameters_media_type);
        push_bytes(&mut out, &self.requested_by);
        push_u64(&mut out, self.requested_at);
        out.extend_from_slice(&self.request_nonce);
        push_u32(&mut out, self.context_commitments.len() as u32);
        for commitment in &self.context_commitments {
            out.extend_from_slice(commitment);
        }
        push_bytes(&mut out, &self.profile.canonical_bytes()?);
        Ok(out)
    }

    /// Returns the content-derived, domain-separated identifier.
    pub fn id(&self) -> Result<IntentId, IntentError> {
        let canonical = self.canonical_bytes()?;
        let digest = DomainSeparatedHash::<ActionIntentDomain>::hash_multiple([
            b"action-intent-v1".as_slice(),
            canonical.as_slice(),
        ])
        .into_inner();
        Ok(IntentId::from_digest(digest))
    }
}

fn is_full_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&ManualEncoder::encode_u32_le(value));
}
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&ManualEncoder::encode_u64_le(value));
}
fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&ManualEncoder::encode_bytes(value));
}
fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}
fn push_option_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn profile() -> GitHubDeploymentIntentV1 {
        let required_contexts = RequiredContexts::AllSubmitted;
        GitHubDeploymentIntentV1 {
            repository_id: 42,
            repository_owner: String::from("diewan"),
            repository_name: String::from("piteka"),
            commit_sha: String::from("0123456789abcdef0123456789abcdef01234567"),
            exact_ref: String::from("0123456789abcdef0123456789abcdef01234567"),
            environment_id: 7,
            environment_name: String::from("production"),
            deployment_gate_policy_digest: required_contexts.gate_policy_id().unwrap(),
            required_contexts,
            payload_commitment: [3; 32],
            artifact_digest: Some([4; 32]),
        }
    }

    fn intent(profile: GitHubDeploymentIntentV1) -> ActionIntent {
        ActionIntent::github_deployment(
            GateProfileId::from_digest([9; 32]),
            vec![8],
            123,
            [7; 32],
            vec![[6; 32]],
            profile,
        )
        .unwrap()
    }

    #[test]
    fn every_profile_field_mutation_changes_the_intent_id() {
        let base = intent(profile()).id().unwrap();
        let mut variants = Vec::new();
        let mut p = profile();
        p.repository_id += 1;
        variants.push(p);
        let mut p = profile();
        p.repository_owner.push('x');
        variants.push(p);
        let mut p = profile();
        p.repository_name.push('x');
        variants.push(p);
        let mut p = profile();
        p.commit_sha.replace_range(0..1, "a");
        p.exact_ref = p.commit_sha.clone();
        variants.push(p);
        let mut p = profile();
        p.environment_id += 1;
        variants.push(p);
        let mut p = profile();
        p.environment_name.push('x');
        variants.push(p);
        let mut p = profile();
        p.required_contexts = RequiredContexts::explicit(vec![String::from("ci")]).unwrap();
        p.deployment_gate_policy_digest = p.required_contexts.gate_policy_id().unwrap();
        variants.push(p);
        let mut p = profile();
        p.payload_commitment[0] ^= 1;
        variants.push(p);
        let mut p = profile();
        p.artifact_digest = None;
        variants.push(p);
        for variant in variants {
            assert_ne!(intent(variant).id().unwrap(), base);
        }
    }

    #[test]
    fn display_names_cannot_override_stable_target_ids() {
        let mut renamed = profile();
        renamed.repository_owner = String::from("attacker");
        renamed.repository_name = String::from("lookalike");
        renamed.environment_name = String::from("not-production");
        assert_eq!(profile().stable_target(), renamed.stable_target());
        assert_ne!(
            intent(profile()).id().unwrap(),
            intent(renamed).id().unwrap()
        );
    }

    #[test]
    fn weakening_and_malicious_normalization_fail_closed() {
        assert_eq!(
            RequiredContexts::explicit(Vec::new()),
            Err(IntentError::InvalidRequiredContexts)
        );
        assert_eq!(
            RequiredContexts::explicit(vec![String::from("ci"), String::from("ci")]),
            Err(IntentError::InvalidRequiredContexts)
        );
        assert_eq!(
            RequiredContexts::explicit(vec![String::from(" ci")]),
            Err(IntentError::InvalidRequiredContexts)
        );
        let mut uppercase = profile();
        uppercase.commit_sha.make_ascii_uppercase();
        uppercase.exact_ref = uppercase.commit_sha.clone();
        assert_eq!(uppercase.validate(), Err(IntentError::InvalidCommitSha));
        let mut moving_ref = profile();
        moving_ref.exact_ref = String::from("main");
        assert_eq!(moving_ref.validate(), Err(IntentError::InvalidCommitSha));
        let mut control = profile();
        control.repository_name = String::from("piteka\nadmin");
        assert_eq!(
            control.validate(),
            Err(IntentError::DisplayFieldTooLong("repository_name"))
        );
        let mut weakened = profile();
        weakened.required_contexts =
            RequiredContexts::explicit(vec![String::from("attacker/status")]).unwrap();
        assert_eq!(weakened.validate(), Err(IntentError::GatePolicyMismatch));
    }

    #[test]
    fn fixed_controls_are_not_caller_settable() {
        let p = profile();
        assert_eq!(p.task(), "deploy");
        assert!(!p.auto_merge());
        assert!(p.production_environment());
        assert!(!p.transient_environment());
    }

    #[test]
    fn github_profile_declares_disjoint_corroborating_and_self_reported_sources() {
        let corroborating =
            <GitHubDeploymentIntentV1 as ProfileValidator>::CORROBORATING_EVIDENCE_SOURCES;
        let self_reported =
            <GitHubDeploymentIntentV1 as ProfileValidator>::SELF_REPORTED_EVIDENCE_SOURCES;
        assert_eq!(
            corroborating,
            &[
                ProfileEvidenceSource::GitHubDeploymentRecord,
                ProfileEvidenceSource::GitHubWebhookDelivery,
                ProfileEvidenceSource::GitHubAuthenticatedEnvironmentConfiguration,
            ]
        );
        assert_eq!(
            self_reported,
            &[ProfileEvidenceSource::ExecutorAttemptRecord]
        );
        assert!(
            corroborating
                .iter()
                .all(|source| !self_reported.contains(source))
        );
        assert_eq!(validate_profile(&profile()), Ok(()));
    }

    #[test]
    fn invalid_profile_source_declarations_fail_closed() {
        struct EmptySources;
        impl ProfileValidator for EmptySources {
            const EXPECTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::ExecutorAttemptRecord];
            const CORROBORATING_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] = &[];
            const SELF_REPORTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] = &[];
        }
        impl profile_sealed::Sealed for EmptySources {
            fn validate_fields(&self) -> Result<(), IntentError> {
                Ok(())
            }
        }
        struct OverlappingSources;
        impl ProfileValidator for OverlappingSources {
            const EXPECTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::GitHubDeploymentRecord];
            const CORROBORATING_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::GitHubDeploymentRecord];
            const SELF_REPORTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::GitHubDeploymentRecord];
        }
        impl profile_sealed::Sealed for OverlappingSources {
            fn validate_fields(&self) -> Result<(), IntentError> {
                Ok(())
            }
        }
        struct MissingSource;
        impl ProfileValidator for MissingSource {
            const EXPECTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] = &[
                ProfileEvidenceSource::ExecutorAttemptRecord,
                ProfileEvidenceSource::GitHubDeploymentRecord,
                ProfileEvidenceSource::GitHubWebhookDelivery,
            ];
            const CORROBORATING_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::GitHubDeploymentRecord];
            const SELF_REPORTED_EVIDENCE_SOURCES: &'static [ProfileEvidenceSource] =
                &[ProfileEvidenceSource::ExecutorAttemptRecord];
        }
        impl profile_sealed::Sealed for MissingSource {
            fn validate_fields(&self) -> Result<(), IntentError> {
                Ok(())
            }
        }
        assert_eq!(
            validate_profile(&EmptySources),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
        assert_eq!(
            validate_profile(&OverlappingSources),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
        assert_eq!(
            validate_profile(&MissingSource),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
    }

    #[test]
    fn generic_fields_are_bound_or_tampering_is_rejected() {
        let base = intent(profile());
        let base_id = base.id().unwrap();
        let mut changed = base.clone();
        changed.protocol_version = ProtocolVersion::new(0, 2);
        assert_eq!(changed.id(), Err(IntentError::UnsupportedVersion));
        let mut changed = base.clone();
        changed.profile_id = GateProfileId::from_digest([11; 32]);
        assert_ne!(changed.id().unwrap(), base_id);
        let mut changed = base.clone();
        changed.requested_by.push(9);
        assert_ne!(changed.id().unwrap(), base_id);
        let mut changed = base.clone();
        changed.requested_at += 1;
        assert_ne!(changed.id().unwrap(), base_id);
        let mut changed = base.clone();
        changed.request_nonce[0] ^= 1;
        assert_ne!(changed.id().unwrap(), base_id);
        let mut changed = base.clone();
        changed.context_commitments.push([12; 32]);
        assert_ne!(changed.id().unwrap(), base_id);
        let mut tampered = base;
        tampered.parameters_commitment[0] ^= 1;
        assert_eq!(
            tampered.id(),
            Err(IntentError::ParametersCommitmentMismatch)
        );
    }
}
