//! Serde-owned wire representations for accountability objects.

use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ActionIntent, GateProfileId, GitHubDeploymentIntentV1,
    IntentError, ObjectVersion, ProfileId, ProtocolVersion, RequiredContexts, default_registry,
};
use serde::{Deserialize, Serialize};

/// Public accountability object kinds carried by a canonical artifact envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityObjectKind {
    /// Exact proposed action.
    ActionIntent,
    /// Signed pre-action authority.
    ActionMandate,
    /// One provider dispatch attempt.
    ExecutionAttempt,
    /// Signed execution outcome report.
    ExecutionReceipt,
    /// Content-addressed evidence node.
    EvidenceNode,
    /// Portable dispute case file.
    DisputeBundle,
    /// Hash-bound verifier inputs.
    VerificationContext,
    /// Dimensioned assurance result.
    AssuranceProfile,
    /// Historical authority compatibility analysis; never an execution mandate.
    AuthorityReconstruction,
    /// Immutable historical bytes plus append-only renewal metadata.
    PreservationEnvelope,
}

/// Transport envelope for bytes produced by the canonical semantic serializer.
///
/// This type deliberately does not serialize semantic objects itself. Producers
/// must call the corresponding `csv-accountability::canonical_bytes` method and
/// place those bytes here unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAccountabilityObjectWire {
    /// Semantic object kind.
    pub kind: AccountabilityObjectKind,
    /// Accountability object schema version.
    pub object_version: u16,
    /// Domain-separated semantic identifier, encoded as lower-case hex.
    pub object_id_hex: String,
    /// Exact canonical semantic bytes, encoded as lower-case hex.
    pub canonical_bytes_hex: String,
}

impl CanonicalAccountabilityObjectWire {
    /// Constructs an envelope and rejects malformed identifiers or empty bytes.
    pub fn new(
        kind: AccountabilityObjectKind,
        object_id: [u8; 32],
        canonical_bytes: &[u8],
    ) -> Result<Self, &'static str> {
        if canonical_bytes.is_empty() {
            return Err("canonical bytes must not be empty");
        }
        let canonical_bytes = csv_codec::preserve_accountability_bytes(canonical_bytes)
            .map_err(|_| "canonical bytes must be within the transport bound")?;
        Ok(Self {
            kind,
            object_version: ACCOUNTABILITY_OBJECT_VERSION.get(),
            object_id_hex: hex::encode(object_id),
            canonical_bytes_hex: hex::encode(canonical_bytes),
        })
    }

    /// Validates and decodes the exact canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, &'static str> {
        if self.object_version != ACCOUNTABILITY_OBJECT_VERSION.get()
            || self.object_id_hex.len() != 64
            || !is_lower_hex(&self.object_id_hex)
            || self.canonical_bytes_hex.is_empty()
            || !self.canonical_bytes_hex.len().is_multiple_of(2)
            || !is_lower_hex(&self.canonical_bytes_hex)
        {
            return Err("invalid canonical accountability envelope");
        }
        let bytes = hex::decode(&self.canonical_bytes_hex)
            .map_err(|_| "invalid canonical accountability envelope")?;
        csv_codec::preserve_accountability_bytes(&bytes)
            .map_err(|_| "invalid canonical accountability envelope")
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Wire selection for GitHub required commit-status contexts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "contexts", deny_unknown_fields)]
pub enum RequiredContextsWire {
    /// Omit the API field and require all submitted contexts.
    AllSubmitted,
    /// Administrator-controlled explicit context names.
    ExplicitNonEmpty(Vec<String>),
}

/// Complete transport envelope for the first GitHub deployment profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubDeploymentIntentV1Wire {
    /// Stable provider repository identifier.
    pub repository_id: u64,
    /// Presentation repository owner.
    pub repository_owner: String,
    /// Presentation repository name.
    pub repository_name: String,
    /// Approved full commit SHA.
    pub commit_sha: String,
    /// Exact Deployments API ref.
    #[serde(rename = "ref")]
    pub exact_ref: String,
    /// Fixed profile task; accepted only when equal to `deploy`.
    pub task: String,
    /// Stable provider environment identifier.
    pub environment_id: u64,
    /// Presentation environment name.
    pub environment_name: String,
    /// Required-context gate mode.
    pub required_contexts: RequiredContextsWire,
    /// Fixed false for the first profile.
    pub auto_merge: bool,
    /// Commitment to the registered correlation payload.
    pub payload_commitment: [u8; 32],
    /// Fixed true for the first profile.
    pub production_environment: bool,
    /// Fixed false for the first profile.
    pub transient_environment: bool,
    /// Optional pre-dispatch artifact digest.
    pub artifact_digest: Option<[u8; 32]>,
    /// Administrator-controlled deployment gate policy digest.
    pub deployment_gate_policy_digest: [u8; 32],
}

/// Complete, profile-agnostic transport envelope for an action intent.
///
/// The profile envelope is carried as opaque canonical bytes (`profile_bytes_hex`) keyed
/// by a registered `profile_id`, so a new profile needs no new wire type. Decoding
/// re-validates the bytes against the registered codec via the default registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntentWire {
    /// Accountability protocol major version.
    pub protocol_version_major: u16,
    /// Accountability protocol minor version.
    pub protocol_version_minor: u16,
    /// Generic intent object version.
    pub intent_version: u16,
    /// Stable, registered profile identifier.
    pub profile_id: String,
    /// Stable action type.
    pub action_type: String,
    /// Stable provider target.
    pub target: Vec<u8>,
    /// Commitment to canonical profile parameters.
    pub parameters_commitment: [u8; 32],
    /// Registered parameter media type.
    pub parameters_media_type: String,
    /// Stable requester identity.
    pub requested_by: Vec<u8>,
    /// Unix request timestamp.
    pub requested_at: u64,
    /// Anti-replay request nonce.
    pub request_nonce: [u8; 32],
    /// Ordered context commitments.
    pub context_commitments: Vec<[u8; 32]>,
    /// Opaque canonical bytes of the registered profile, lower-case hex.
    pub profile_bytes_hex: String,
}

impl From<&RequiredContexts> for RequiredContextsWire {
    fn from(value: &RequiredContexts) -> Self {
        match value {
            RequiredContexts::AllSubmitted => Self::AllSubmitted,
            RequiredContexts::ExplicitNonEmpty(contexts) => {
                Self::ExplicitNonEmpty(contexts.clone())
            }
        }
    }
}

impl TryFrom<RequiredContextsWire> for RequiredContexts {
    type Error = IntentError;

    fn try_from(value: RequiredContextsWire) -> Result<Self, Self::Error> {
        match value {
            RequiredContextsWire::AllSubmitted => Ok(Self::AllSubmitted),
            RequiredContextsWire::ExplicitNonEmpty(contexts) => Self::explicit(contexts),
        }
    }
}

impl From<&GitHubDeploymentIntentV1> for GitHubDeploymentIntentV1Wire {
    fn from(value: &GitHubDeploymentIntentV1) -> Self {
        Self {
            repository_id: value.repository_id,
            repository_owner: value.repository_owner.clone(),
            repository_name: value.repository_name.clone(),
            commit_sha: value.commit_sha.clone(),
            exact_ref: value.exact_ref.clone(),
            task: value.task().into(),
            environment_id: value.environment_id,
            environment_name: value.environment_name.clone(),
            required_contexts: (&value.required_contexts).into(),
            auto_merge: value.auto_merge(),
            payload_commitment: value.payload_commitment,
            production_environment: value.production_environment(),
            transient_environment: value.transient_environment(),
            artifact_digest: value.artifact_digest,
            deployment_gate_policy_digest: value.deployment_gate_policy_digest.into_bytes(),
        }
    }
}

impl TryFrom<GitHubDeploymentIntentV1Wire> for GitHubDeploymentIntentV1 {
    type Error = IntentError;

    fn try_from(value: GitHubDeploymentIntentV1Wire) -> Result<Self, Self::Error> {
        if value.task != "deploy" {
            return Err(IntentError::UnsupportedTask);
        }
        if value.auto_merge {
            return Err(IntentError::AutoMergeForbidden);
        }
        if !value.production_environment || value.transient_environment {
            return Err(IntentError::InvalidEnvironmentClassification);
        }
        let profile = Self {
            repository_id: value.repository_id,
            repository_owner: value.repository_owner,
            repository_name: value.repository_name,
            commit_sha: value.commit_sha,
            exact_ref: value.exact_ref,
            environment_id: value.environment_id,
            environment_name: value.environment_name,
            required_contexts: value.required_contexts.try_into()?,
            payload_commitment: value.payload_commitment,
            artifact_digest: value.artifact_digest,
            deployment_gate_policy_digest: GateProfileId::from_digest(
                value.deployment_gate_policy_digest,
            ),
        };
        profile.validate()?;
        Ok(profile)
    }
}

impl From<&ActionIntent> for ActionIntentWire {
    fn from(value: &ActionIntent) -> Self {
        Self {
            protocol_version_major: value.protocol_version.major(),
            protocol_version_minor: value.protocol_version.minor(),
            intent_version: value.intent_version.get(),
            profile_id: value.profile_id.as_str().into(),
            action_type: value.action_type.clone(),
            target: value.target.clone(),
            parameters_commitment: value.parameters_commitment,
            parameters_media_type: value.parameters_media_type.clone(),
            requested_by: value.requested_by.clone(),
            requested_at: value.requested_at,
            request_nonce: value.request_nonce,
            context_commitments: value.context_commitments.clone(),
            profile_bytes_hex: hex::encode(&value.profile_bytes),
        }
    }
}

impl TryFrom<ActionIntentWire> for ActionIntent {
    type Error = IntentError;

    fn try_from(value: ActionIntentWire) -> Result<Self, Self::Error> {
        if value.intent_version != ACCOUNTABILITY_OBJECT_VERSION.get() {
            return Err(IntentError::UnsupportedVersion);
        }
        let profile_bytes = hex::decode(&value.profile_bytes_hex)
            .map_err(|_| IntentError::MalformedProfileBytes)?;
        let intent = Self {
            protocol_version: ProtocolVersion::new(
                value.protocol_version_major,
                value.protocol_version_minor,
            ),
            intent_version: ObjectVersion::try_new(value.intent_version)
                .map_err(|_| IntentError::EmptyField("intent_version"))?,
            profile_id: ProfileId::new(value.profile_id)?,
            action_type: value.action_type,
            target: value.target,
            parameters_commitment: value.parameters_commitment,
            parameters_media_type: value.parameters_media_type,
            requested_by: value.requested_by,
            requested_at: value.requested_at,
            request_nonce: value.request_nonce,
            context_commitments: value.context_commitments,
            profile_bytes,
        };
        intent.validate()?;
        // Independently re-check the target and parameters commitment against the
        // registered codec, so a wire envelope cannot claim bindings its profile bytes
        // do not support.
        let registry = default_registry();
        let descriptor = registry
            .descriptor(&intent.profile_id)
            .ok_or(IntentError::UnregisteredProfile)?;
        let codec = registry
            .codec(&intent.profile_id)
            .ok_or(IntentError::UnregisteredProfile)?;
        intent.verify_with_codec(descriptor, codec)?;
        Ok(intent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_accountability::ActionIntent;

    fn wire_profile() -> GitHubDeploymentIntentV1Wire {
        let policy = RequiredContexts::AllSubmitted.gate_policy_id().unwrap();
        GitHubDeploymentIntentV1Wire {
            repository_id: 42,
            repository_owner: "diewan".into(),
            repository_name: "piteka".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            exact_ref: "0123456789abcdef0123456789abcdef01234567".into(),
            task: "deploy".into(),
            environment_id: 7,
            environment_name: "production".into(),
            required_contexts: RequiredContextsWire::AllSubmitted,
            auto_merge: false,
            payload_commitment: [3; 32],
            production_environment: true,
            transient_environment: false,
            artifact_digest: None,
            deployment_gate_policy_digest: policy.into_bytes(),
        }
    }

    #[test]
    fn profile_round_trips_without_losing_deployment_fields() {
        let semantic = GitHubDeploymentIntentV1::try_from(wire_profile()).unwrap();
        assert_eq!(
            GitHubDeploymentIntentV1Wire::from(&semantic),
            wire_profile()
        );
        assert_eq!(semantic.task(), "deploy");
        assert!(!semantic.auto_merge());
    }

    #[test]
    fn caller_cannot_weaken_fixed_controls() {
        let mut task = wire_profile();
        task.task = "destroy".into();
        assert_eq!(
            GitHubDeploymentIntentV1::try_from(task),
            Err(IntentError::UnsupportedTask)
        );
        let mut merge = wire_profile();
        merge.auto_merge = true;
        assert_eq!(
            GitHubDeploymentIntentV1::try_from(merge),
            Err(IntentError::AutoMergeForbidden)
        );
        let mut transient = wire_profile();
        transient.transient_environment = true;
        assert_eq!(
            GitHubDeploymentIntentV1::try_from(transient),
            Err(IntentError::InvalidEnvironmentClassification)
        );
    }

    #[test]
    fn empty_contexts_and_arbitrary_payload_are_rejected() {
        let mut empty = wire_profile();
        empty.required_contexts = RequiredContextsWire::ExplicitNonEmpty(Vec::new());
        assert_eq!(
            GitHubDeploymentIntentV1::try_from(empty),
            Err(IntentError::InvalidRequiredContexts)
        );

        let json = serde_json::to_value(wire_profile()).unwrap();
        let mut object = json.as_object().unwrap().clone();
        object.insert("payload".into(), serde_json::json!({"agent": "controlled"}));
        assert!(serde_json::from_value::<GitHubDeploymentIntentV1Wire>(object.into()).is_err());
    }

    #[test]
    fn generic_tampering_cannot_override_stable_profile_ids() {
        let profile = GitHubDeploymentIntentV1::try_from(wire_profile()).unwrap();
        let intent =
            ActionIntent::github_deployment(vec![8], 1, [7; 32], Vec::new(), profile).unwrap();
        let mut wire = ActionIntentWire::from(&intent);
        wire.target[0] ^= 1;
        assert_eq!(
            ActionIntent::try_from(wire),
            Err(IntentError::TargetMismatch)
        );
        assert_eq!(intent.intent_version, ACCOUNTABILITY_OBJECT_VERSION);
    }

    #[test]
    fn canonical_envelope_rejects_noncanonical_hex_and_unknown_fields() {
        let envelope = CanonicalAccountabilityObjectWire::new(
            AccountabilityObjectKind::ActionIntent,
            [0xab; 32],
            &[2, 3],
        )
        .unwrap();
        assert_eq!(envelope.canonical_bytes().unwrap(), vec![2, 3]);

        let mut uppercase = envelope.clone();
        uppercase.object_id_hex.make_ascii_uppercase();
        assert!(uppercase.canonical_bytes().is_err());

        let mut json = serde_json::to_value(envelope).unwrap();
        json.as_object_mut().unwrap().insert(
            "semantic_object".into(),
            serde_json::json!({"forged": true}),
        );
        assert!(serde_json::from_value::<CanonicalAccountabilityObjectWire>(json).is_err());
    }
}
