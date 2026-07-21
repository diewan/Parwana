//! Canonical action-intent and profile-envelope semantics.

use alloc::{string::String, vec::Vec};

use csv_codec::ManualEncoder;
use csv_hash::{ActionIntentDomain, DomainSeparatedHash, GateProfileDomain};

use crate::id::{ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION};
use crate::profile::{
    EvidenceSourceClass, EvidenceSourceDecl, EvidenceSourceId, ProfileCodec, ProfileDescriptor,
    ProfileId, QuarantineReleaseRule,
};
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
    /// A stable profile or evidence-source identifier was malformed.
    InvalidProfileId,
    /// Profile parameter bytes were not the canonical encoding of a valid profile value.
    MalformedProfileBytes,
    /// The intent's action type resolves to no registered profile.
    UnregisteredProfile,
    /// A profile id was registered more than once.
    DuplicateProfile,
}

/// Stable, namespaced identifier of the first GitHub deployment profile.
pub const GITHUB_DEPLOYMENT_PROFILE_ID: &str =
    "org.diewan.accountability.github-deployment.intent.v1";
/// Stable action type bound into a GitHub deployment intent.
pub const GITHUB_DEPLOYMENT_ACTION_TYPE: &str = "github.deployment";
/// Domain separator hashed with the profile bytes to form the parameters commitment.
pub const GITHUB_DEPLOYMENT_PARAMETERS_DOMAIN_TAG: &[u8] = b"github-deployment-parameters-v1";

/// Stable evidence-source identifier: the executor's own execution-attempt record.
pub const EVIDENCE_EXECUTOR_ATTEMPT_RECORD: &str = "evidence.executor.attempt-record";
/// Stable evidence-source identifier: GitHub's accepted Deployments API record.
pub const EVIDENCE_GITHUB_DEPLOYMENT_RECORD: &str = "evidence.github.deployment-record";
/// Stable evidence-source identifier: a correlated, authenticated GitHub webhook delivery.
pub const EVIDENCE_GITHUB_WEBHOOK_DELIVERY: &str = "evidence.github.webhook-delivery";
/// Stable evidence-source identifier: authenticated GitHub environment-protection config.
pub const EVIDENCE_GITHUB_ENVIRONMENT_CONFIGURATION: &str =
    "evidence.github.authenticated-environment-configuration";

/// Returns the registered descriptor for the first GitHub deployment profile.
pub fn github_deployment_descriptor() -> ProfileDescriptor {
    ProfileDescriptor {
        profile_id: ProfileId::new(GITHUB_DEPLOYMENT_PROFILE_ID)
            .expect("static github profile id is valid"),
        action_type: String::from(GITHUB_DEPLOYMENT_ACTION_TYPE),
        parameters_media_type: String::from(PARAMETERS_MEDIA_TYPE_V1),
        parameters_domain_tag: GITHUB_DEPLOYMENT_PARAMETERS_DOMAIN_TAG.to_vec(),
        evidence_sources: alloc::vec![
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(EVIDENCE_EXECUTOR_ATTEMPT_RECORD)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::Executor,
            ),
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(EVIDENCE_GITHUB_DEPLOYMENT_RECORD)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::ProviderCorroborating,
            ),
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(EVIDENCE_GITHUB_WEBHOOK_DELIVERY)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::ProviderCorroborating,
            ),
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(EVIDENCE_GITHUB_ENVIRONMENT_CONFIGURATION)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::ProviderCorroborating,
            ),
            // Optional single-use corroboration external to both executor and provider
            // (Phase B). Registered here so an independent seal consumption/anchor is a
            // recognized evidence source without a core edit (Master Plan §5.9, §36).
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(crate::anchor::EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::ExternalAnchor,
            ),
            EvidenceSourceDecl::new(
                EvidenceSourceId::new(crate::anchor::EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR)
                    .expect("static evidence id is valid"),
                EvidenceSourceClass::ExternalAnchor,
            ),
        ],
        // The first GitHub profile has no sufficient absence predicate: after ambiguous
        // dispatch no query can prove non-acceptance, so a quarantine is never released.
        quarantine_release: QuarantineReleaseRule::NeverReleasable,
        max_context_commitments: MAX_CONTEXT_COMMITMENTS,
        max_identity_bytes: MAX_IDENTITY_BYTES,
    }
}

/// The registerable codec for the first GitHub deployment profile.
///
/// It decodes and validates a [`GitHubDeploymentIntentV1`] from its canonical bytes, so
/// an independent verifier reconstructs and re-checks the profile from bundle bytes alone.
pub struct GitHubDeploymentCodec {
    descriptor: ProfileDescriptor,
}

impl Default for GitHubDeploymentCodec {
    fn default() -> Self {
        Self {
            descriptor: github_deployment_descriptor(),
        }
    }
}

impl ProfileCodec for GitHubDeploymentCodec {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn validate_canonical_bytes(&self, profile_bytes: &[u8]) -> Result<Vec<u8>, IntentError> {
        let profile = GitHubDeploymentIntentV1::from_canonical_bytes(profile_bytes)?;
        Ok(profile.stable_target())
    }
}

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
        self.validate_profile_fields()
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

    /// Decodes and validates a profile from its exact canonical byte encoding.
    ///
    /// Fails closed on any non-canonical, truncated, or trailing input: the decoded
    /// value must re-encode to precisely `bytes`, so an independent verifier reproduces
    /// the profile (and therefore the intent's parameters commitment) from bytes alone.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, IntentError> {
        let mut cur = Cursor::new(bytes);
        let version = cur.read_u16()?;
        if version != ACCOUNTABILITY_OBJECT_VERSION.get() {
            return Err(IntentError::UnsupportedVersion);
        }
        let repository_id = cur.read_u64()?;
        let repository_owner = cur.read_string()?;
        let repository_name = cur.read_string()?;
        let commit_sha = cur.read_string()?;
        let exact_ref = cur.read_string()?;
        let task = cur.read_string()?;
        if task != GITHUB_DEPLOYMENT_TASK_V1 {
            return Err(IntentError::UnsupportedTask);
        }
        let environment_id = cur.read_u64()?;
        let environment_name = cur.read_string()?;
        let required_contexts = match cur.read_u8()? {
            0 => RequiredContexts::AllSubmitted,
            1 => {
                let count = cur.read_u32()? as usize;
                if count > MAX_REQUIRED_CONTEXTS {
                    return Err(IntentError::InvalidRequiredContexts);
                }
                let mut contexts = Vec::with_capacity(count);
                for _ in 0..count {
                    contexts.push(cur.read_string()?);
                }
                RequiredContexts::explicit(contexts)?
            }
            _ => return Err(IntentError::MalformedProfileBytes),
        };
        if cur.read_u8()? != 0 {
            return Err(IntentError::AutoMergeForbidden);
        }
        let payload_commitment = cur.read_hash()?;
        if cur.read_u8()? != 1 || cur.read_u8()? != 0 {
            return Err(IntentError::InvalidEnvironmentClassification);
        }
        let artifact_digest = match cur.read_u8()? {
            0 => None,
            1 => Some(cur.read_hash()?),
            _ => return Err(IntentError::MalformedProfileBytes),
        };
        let deployment_gate_policy_digest = GateProfileId::from_digest(cur.read_hash()?);
        if !cur.is_empty() {
            return Err(IntentError::MalformedProfileBytes);
        }
        let profile = Self {
            repository_id,
            repository_owner,
            repository_name,
            commit_sha,
            exact_ref,
            environment_id,
            environment_name,
            required_contexts,
            payload_commitment,
            artifact_digest,
            deployment_gate_policy_digest,
        };
        profile.validate()?;
        // Reject any encoding that is valid-looking but not the unique canonical form.
        if profile.canonical_bytes()? != bytes {
            return Err(IntentError::MalformedProfileBytes);
        }
        Ok(profile)
    }
}

/// Minimal fail-closed cursor over the little-endian manual encoding used by profiles.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], IntentError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(IntentError::MalformedProfileBytes)?;
        if end > self.bytes.len() {
            return Err(IntentError::MalformedProfileBytes);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, IntentError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, IntentError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, IntentError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, IntentError> {
        let bytes = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], IntentError> {
        let bytes = self.take(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    fn read_string(&mut self) -> Result<String, IntentError> {
        let len = self.read_u32()? as usize;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(String::from)
            .map_err(|_| IntentError::MalformedProfileBytes)
    }
}

/// Exact generic action proposal bound to a registered provider profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionIntent {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of the generic intent.
    pub intent_version: ObjectVersion,
    /// Stable, registered profile identifier.
    pub profile_id: ProfileId,
    /// Stable action type (bound by the registered descriptor).
    pub action_type: String,
    /// Stable provider target bytes (derived by the profile codec).
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
    /// Canonical bytes of the registered profile envelope.
    pub profile_bytes: Vec<u8>,
}

impl ActionIntent {
    /// Constructs a validated action intent for any registered profile.
    ///
    /// The `descriptor` supplies the stable action type, media type, size limits, and the
    /// domain tag used for the parameters commitment; the `codec` validates
    /// `profile_bytes` as the profile's exact canonical encoding and derives the stable
    /// target. Neither the action type nor the target is taken from the caller.
    pub fn new(
        descriptor: &ProfileDescriptor,
        codec: &dyn ProfileCodec,
        profile_bytes: Vec<u8>,
        requested_by: Vec<u8>,
        requested_at: u64,
        request_nonce: [u8; 32],
        context_commitments: Vec<[u8; 32]>,
    ) -> Result<Self, IntentError> {
        descriptor.validate()?;
        let target = codec.validate_canonical_bytes(&profile_bytes)?;
        if requested_by.is_empty() {
            return Err(IntentError::EmptyField("requested_by"));
        }
        if requested_by.len() > descriptor.max_identity_bytes {
            return Err(IntentError::IdentityTooLong);
        }
        if context_commitments.len() > descriptor.max_context_commitments {
            return Err(IntentError::TooManyContextCommitments);
        }
        let parameters_commitment = DomainSeparatedHash::<GateProfileDomain>::hash_multiple([
            descriptor.parameters_domain_tag.as_slice(),
            profile_bytes.as_slice(),
        ])
        .into_inner();
        Ok(Self {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            intent_version: ACCOUNTABILITY_OBJECT_VERSION,
            profile_id: descriptor.profile_id.clone(),
            action_type: descriptor.action_type.clone(),
            target,
            parameters_commitment,
            parameters_media_type: descriptor.parameters_media_type.clone(),
            requested_by,
            requested_at,
            request_nonce,
            context_commitments,
            profile_bytes,
        })
    }

    /// Constructs a validated GitHub deployment action intent.
    ///
    /// Thin migration shim over [`Self::new`] using the registered GitHub deployment
    /// descriptor and codec; kept until every caller speaks generic intents.
    pub fn github_deployment(
        requested_by: Vec<u8>,
        requested_at: u64,
        request_nonce: [u8; 32],
        context_commitments: Vec<[u8; 32]>,
        profile: GitHubDeploymentIntentV1,
    ) -> Result<Self, IntentError> {
        let codec = GitHubDeploymentCodec::default();
        let profile_bytes = profile.canonical_bytes()?;
        Self::new(
            codec.descriptor(),
            &codec,
            profile_bytes,
            requested_by,
            requested_at,
            request_nonce,
            context_commitments,
        )
    }

    /// Structural validation of the generic intent envelope.
    ///
    /// Checks versions, identifier well-formedness, and identity/context bounds. It does
    /// not re-derive the target or parameters commitment — those require the registered
    /// [`ProfileCodec`]; use [`Self::verify_with_codec`] (or a [`ProfileRegistry`]) for
    /// that independent re-check.
    ///
    /// [`ProfileRegistry`]: crate::registry::ProfileRegistry
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION {
            return Err(IntentError::UnsupportedVersion);
        }
        if self.intent_version != ACCOUNTABILITY_OBJECT_VERSION {
            return Err(IntentError::UnsupportedVersion);
        }
        // Reject a malformed profile identifier.
        ProfileId::new(self.profile_id.as_str())?;
        if self.action_type.is_empty() {
            return Err(IntentError::EmptyField("action_type"));
        }
        if self.parameters_media_type.is_empty() {
            return Err(IntentError::EmptyField("parameters_media_type"));
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

    /// Independently re-derives the target and parameters commitment from `codec` and
    /// checks they match the stored fields.
    ///
    /// This is the profile-aware half of verification: any tampering with `profile_bytes`,
    /// `target`, `parameters_commitment`, `action_type`, or `parameters_media_type` fails
    /// closed. A verifier obtains `descriptor`/`codec` for `self.profile_id` from the
    /// registry.
    pub fn verify_with_codec(
        &self,
        descriptor: &ProfileDescriptor,
        codec: &dyn ProfileCodec,
    ) -> Result<(), IntentError> {
        self.validate()?;
        if self.profile_id != descriptor.profile_id || self.action_type != descriptor.action_type {
            return Err(IntentError::UnregisteredProfile);
        }
        let target = codec.validate_canonical_bytes(&self.profile_bytes)?;
        if self.target != target {
            return Err(IntentError::TargetMismatch);
        }
        let expected = DomainSeparatedHash::<GateProfileDomain>::hash_multiple([
            descriptor.parameters_domain_tag.as_slice(),
            self.profile_bytes.as_slice(),
        ])
        .into_inner();
        if self.parameters_commitment != expected
            || self.parameters_media_type != descriptor.parameters_media_type
        {
            return Err(IntentError::ParametersCommitmentMismatch);
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
        push_string(&mut out, self.profile_id.as_str());
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
        push_bytes(&mut out, &self.profile_bytes);
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
        ActionIntent::github_deployment(vec![8], 123, [7; 32], vec![[6; 32]], profile).unwrap()
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
    fn github_descriptor_declares_disjoint_evidence_source_classes() {
        let descriptor = github_deployment_descriptor();
        assert_eq!(descriptor.validate(), Ok(()));
        let executor: Vec<_> = descriptor
            .evidence_sources
            .iter()
            .filter(|decl| matches!(decl.class, EvidenceSourceClass::Executor))
            .map(|decl| decl.id.as_str())
            .collect();
        let corroborating: Vec<_> = descriptor
            .evidence_sources
            .iter()
            .filter(|decl| decl.class.is_corroborating())
            .map(|decl| decl.id.as_str())
            .collect();
        let external_anchor: Vec<_> = descriptor
            .evidence_sources
            .iter()
            .filter(|decl| matches!(decl.class, EvidenceSourceClass::ExternalAnchor))
            .map(|decl| decl.id.as_str())
            .collect();
        assert_eq!(executor, vec![EVIDENCE_EXECUTOR_ATTEMPT_RECORD]);
        assert_eq!(
            corroborating,
            vec![
                EVIDENCE_GITHUB_DEPLOYMENT_RECORD,
                EVIDENCE_GITHUB_WEBHOOK_DELIVERY,
                EVIDENCE_GITHUB_ENVIRONMENT_CONFIGURATION,
                // External-anchor sources are corroborating too (Phase B).
                crate::anchor::EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD,
                crate::anchor::EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR,
            ]
        );
        assert_eq!(
            external_anchor,
            vec![
                crate::anchor::EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD,
                crate::anchor::EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR,
            ]
        );
    }

    #[test]
    fn invalid_descriptor_evidence_declarations_fail_closed() {
        let executor = EvidenceSourceDecl::new(
            EvidenceSourceId::new(EVIDENCE_EXECUTOR_ATTEMPT_RECORD).unwrap(),
            EvidenceSourceClass::Executor,
        );
        let corroborating = EvidenceSourceDecl::new(
            EvidenceSourceId::new(EVIDENCE_GITHUB_DEPLOYMENT_RECORD).unwrap(),
            EvidenceSourceClass::ProviderCorroborating,
        );
        let with_sources = |sources: Vec<EvidenceSourceDecl>| ProfileDescriptor {
            evidence_sources: sources,
            ..github_deployment_descriptor()
        };
        // Empty inventory.
        assert_eq!(
            with_sources(Vec::new()).validate(),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
        // No executor-class source.
        assert_eq!(
            with_sources(vec![corroborating.clone()]).validate(),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
        // No corroborating source.
        assert_eq!(
            with_sources(vec![executor.clone()]).validate(),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
        // Duplicate identifier.
        assert_eq!(
            with_sources(vec![executor.clone(), corroborating.clone(), corroborating]).validate(),
            Err(IntentError::InvalidEvidenceSourceDeclaration)
        );
    }

    #[test]
    fn profile_bytes_round_trip_and_noncanonical_input_fails_closed() {
        let profile = profile();
        let bytes = profile.canonical_bytes().unwrap();
        assert_eq!(
            GitHubDeploymentIntentV1::from_canonical_bytes(&bytes),
            Ok(profile)
        );
        // Trailing byte.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            GitHubDeploymentIntentV1::from_canonical_bytes(&trailing),
            Err(IntentError::MalformedProfileBytes)
        );
        // Truncated.
        assert_eq!(
            GitHubDeploymentIntentV1::from_canonical_bytes(&bytes[..bytes.len() - 1]),
            Err(IntentError::MalformedProfileBytes)
        );
    }

    #[test]
    fn generic_fields_are_bound_or_tampering_is_rejected() {
        let base = intent(profile());
        let base_id = base.id().unwrap();
        let codec = GitHubDeploymentCodec::default();
        assert_eq!(base.verify_with_codec(codec.descriptor(), &codec), Ok(()));
        let mut changed = base.clone();
        changed.protocol_version = ProtocolVersion::new(0, 2);
        assert_eq!(changed.id(), Err(IntentError::UnsupportedVersion));
        let mut changed = base.clone();
        changed.profile_id = ProfileId::new("org.diewan.accountability.other.intent.v1").unwrap();
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
        // A tampered commitment changes the id (tamper-evident) and fails codec re-check.
        let mut tampered = base;
        tampered.parameters_commitment[0] ^= 1;
        assert_ne!(tampered.id().unwrap(), base_id);
        assert_eq!(
            tampered.verify_with_codec(codec.descriptor(), &codec),
            Err(IntentError::ParametersCommitmentMismatch)
        );
    }
}
