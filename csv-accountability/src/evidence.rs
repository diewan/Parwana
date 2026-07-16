//! Evidence vocabulary and bounded graph semantics.

use alloc::{string::String, vec::Vec};

use csv_hash::{DomainSeparatedHash, EvidenceNodeDomain};

use crate::EvidenceNodeId;

/// Maximum evidence nodes in one validated graph.
pub const MAX_EVIDENCE_NODES: usize = 1_024;
/// Maximum direct relationships from one evidence node.
pub const MAX_EVIDENCE_RELATIONSHIPS: usize = 64;
/// Maximum evidence graph depth.
pub const MAX_EVIDENCE_DEPTH: usize = 64;
/// Maximum producer, locator, media-type, or classification bytes.
pub const MAX_EVIDENCE_TEXT_BYTES: usize = 1_024;

/// Stable registry identifier for a claim.
pub const CLAIM_REGISTRY_ID: &str = "org.diewan.evidence.claim.v1";
/// Stable registry identifier for an observation.
pub const OBSERVATION_REGISTRY_ID: &str = "org.diewan.evidence.observation.v1";
/// Stable registry identifier for an attestation.
pub const ATTESTATION_REGISTRY_ID: &str = "org.diewan.evidence.attestation.v1";
/// Stable registry identifier for an explicit evidence gap.
pub const EVIDENCE_GAP_REGISTRY_ID: &str = "org.diewan.evidence.gap.v1";

/// Reserved v0.2 registry identifiers; no v0.1 constructor accepts these.
pub const RESERVED_EVIDENCE_REGISTRY_IDS: &[&str] = &[
    "org.diewan.evidence.anchor.v1",
    "org.diewan.evidence.custody-record.v1",
    "org.diewan.evidence.identity-binding.v1",
    "org.diewan.evidence.revocation-record.v1",
    "org.diewan.evidence.policy-snapshot.v1",
    "org.diewan.evidence.counterclaim.v1",
    "org.diewan.evidence.contradiction.v1",
    "org.diewan.evidence.disclosure-commitment.v1",
    "org.diewan.evidence.preservation-envelope.v1",
];

/// Source-locator disclosure policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceLocator {
    /// A locator safe to disclose in this bundle.
    Disclosed(String),
    /// Only a commitment is disclosed.
    Withheld([u8; 32]),
}

/// Authenticity material attached by the producer without pre-judging validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticityMaterial {
    /// Registered authenticity scheme.
    pub scheme_id: String,
    /// Digest of the exact material retained or disclosed elsewhere.
    pub material_digest: [u8; 32],
}

/// One of the four evidence meanings implemented in v0.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    /// A proposition asserted by a producer.
    Claim {
        /// Digest of the exact asserted proposition.
        proposition_digest: [u8; 32],
    },
    /// A source-bounded record of what was observed.
    Observation {
        /// Registered observation method.
        method_id: String,
    },
    /// A producer's signed or otherwise authenticatable statement.
    Attestation {
        /// Identity claimed by the attesting party.
        attester_identity: Vec<u8>,
    },
    /// An explicit statement that required evidence is unavailable or withheld.
    EvidenceGap {
        /// Registered missing-evidence class.
        missing_registry_id: String,
        /// Human-display-safe reason commitment, not an assertion of non-occurrence.
        reason_digest: [u8; 32],
    },
}

impl EvidenceKind {
    /// Returns the collision-resistant registered type identifier.
    pub const fn registry_id(&self) -> &'static str {
        match self {
            Self::Claim { .. } => CLAIM_REGISTRY_ID,
            Self::Observation { .. } => OBSERVATION_REGISTRY_ID,
            Self::Attestation { .. } => ATTESTATION_REGISTRY_ID,
            Self::EvidenceGap { .. } => EVIDENCE_GAP_REGISTRY_ID,
        }
    }
}

/// Content-addressed evidence node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceNode {
    /// Exact semantic node kind.
    pub kind: EvidenceKind,
    /// Stable producer identity.
    pub producer_identity: Vec<u8>,
    /// Time this material was collected.
    pub collected_at: u64,
    /// Producer-reported event time, if one exists.
    pub asserted_event_at: Option<u64>,
    /// Digest of the exact evidence content.
    pub content_digest: [u8; 32],
    /// Registered content media type.
    pub media_type: String,
    /// Disclosure-aware source locator.
    pub source_locator: SourceLocator,
    /// Authenticity material, if available.
    pub authenticity: Option<AuthenticityMaterial>,
    /// Registered disclosure classification.
    pub disclosure_classification: String,
    /// Canonically sorted identifiers of prerequisite/supporting nodes.
    pub relationships: Vec<EvidenceNodeId>,
}

/// Invalid evidence semantics or graph structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// A required field is absent, zero, or exceeds its bound.
    InvalidField(&'static str),
    /// A claim was encoded as an observation or vice versa.
    SemanticConfusion,
    /// A registry identifier collides with another implemented or reserved type.
    RegistryCollision,
    /// A relationship names a node absent from the graph.
    MissingRelationship,
    /// The graph contains a cycle.
    Cycle,
    /// Node count, fanout, or depth exceeds protocol bounds.
    BoundsExceeded,
    /// The supplied identifier does not match canonical node bytes.
    IdentifierMismatch,
}

impl EvidenceNode {
    /// Validates local node semantics and bounds.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bytes(&self.producer_identity, "producer_identity")?;
        validate_text(&self.media_type, "media_type")?;
        validate_text(&self.disclosure_classification, "disclosure_classification")?;
        if self.content_digest == [0; 32]
            || self
                .asserted_event_at
                .is_some_and(|event| event > self.collected_at)
        {
            return Err(EvidenceError::InvalidField("time_or_digest"));
        }
        match &self.source_locator {
            SourceLocator::Disclosed(value) => validate_text(value, "source_locator")?,
            SourceLocator::Withheld(digest) if *digest == [0; 32] => {
                return Err(EvidenceError::InvalidField("source_locator"));
            }
            SourceLocator::Withheld(_) => {}
        }
        if let Some(authenticity) = &self.authenticity {
            validate_text(&authenticity.scheme_id, "authenticity_scheme")?;
            if authenticity.material_digest == [0; 32] {
                return Err(EvidenceError::InvalidField("authenticity_digest"));
            }
        }
        match &self.kind {
            EvidenceKind::Claim { proposition_digest } if *proposition_digest == [0; 32] => {
                return Err(EvidenceError::InvalidField("proposition_digest"));
            }
            EvidenceKind::Observation { method_id } => {
                validate_text(method_id, "observation_method")?;
                if method_id.contains("claim") {
                    return Err(EvidenceError::SemanticConfusion);
                }
            }
            EvidenceKind::Attestation { attester_identity } => {
                validate_bytes(attester_identity, "attester_identity")?;
                if self.authenticity.is_none() {
                    return Err(EvidenceError::InvalidField("attestation_authenticity"));
                }
            }
            EvidenceKind::EvidenceGap {
                missing_registry_id,
                reason_digest,
            } => {
                validate_text(missing_registry_id, "missing_registry_id")?;
                if *reason_digest == [0; 32] {
                    return Err(EvidenceError::InvalidField("reason_digest"));
                }
            }
            EvidenceKind::Claim { .. } => {}
        }
        if self.relationships.len() > MAX_EVIDENCE_RELATIONSHIPS
            || self.relationships.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EvidenceError::BoundsExceeded);
        }
        Ok(())
    }

    /// Returns deterministic canonical bytes for hashing and independent verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        let mut out = Vec::new();
        push_text(&mut out, self.kind.registry_id());
        match &self.kind {
            EvidenceKind::Claim { proposition_digest } => out.extend_from_slice(proposition_digest),
            EvidenceKind::Observation { method_id } => push_text(&mut out, method_id),
            EvidenceKind::Attestation { attester_identity } => {
                push_bytes(&mut out, attester_identity)
            }
            EvidenceKind::EvidenceGap {
                missing_registry_id,
                reason_digest,
            } => {
                push_text(&mut out, missing_registry_id);
                out.extend_from_slice(reason_digest);
            }
        }
        push_bytes(&mut out, &self.producer_identity);
        push_u64(&mut out, self.collected_at);
        push_option_u64(&mut out, self.asserted_event_at);
        out.extend_from_slice(&self.content_digest);
        push_text(&mut out, &self.media_type);
        match &self.source_locator {
            SourceLocator::Disclosed(value) => {
                out.push(0);
                push_text(&mut out, value);
            }
            SourceLocator::Withheld(digest) => {
                out.push(1);
                out.extend_from_slice(digest);
            }
        }
        match &self.authenticity {
            Some(value) => {
                out.push(1);
                push_text(&mut out, &value.scheme_id);
                out.extend_from_slice(&value.material_digest);
            }
            None => out.push(0),
        }
        push_text(&mut out, &self.disclosure_classification);
        push_u32(&mut out, self.relationships.len() as u32);
        for relationship in &self.relationships {
            out.extend_from_slice(relationship.as_bytes());
        }
        Ok(out)
    }

    /// Derives this node's domain-separated content identifier.
    pub fn id(&self) -> Result<EvidenceNodeId, EvidenceError> {
        let bytes = self.canonical_bytes()?;
        Ok(EvidenceNodeId::from_digest(
            DomainSeparatedHash::<EvidenceNodeDomain>::hash(&bytes).into_inner(),
        ))
    }
}

/// Validates content identifiers, missing edges, cycles, and graph bounds.
pub fn validate_evidence_graph(
    nodes: &[(EvidenceNodeId, EvidenceNode)],
) -> Result<(), EvidenceError> {
    if nodes.len() > MAX_EVIDENCE_NODES {
        return Err(EvidenceError::BoundsExceeded);
    }
    for (index, (id, node)) in nodes.iter().enumerate() {
        if *id != node.id()? {
            return Err(EvidenceError::IdentifierMismatch);
        }
        let mut path = Vec::new();
        visit(nodes, index, &mut path, 0)?;
    }
    Ok(())
}

fn visit(
    nodes: &[(EvidenceNodeId, EvidenceNode)],
    index: usize,
    path: &mut Vec<usize>,
    depth: usize,
) -> Result<(), EvidenceError> {
    if depth > MAX_EVIDENCE_DEPTH {
        return Err(EvidenceError::BoundsExceeded);
    }
    if path.contains(&index) {
        return Err(EvidenceError::Cycle);
    }
    path.push(index);
    for relationship in &nodes[index].1.relationships {
        let next = nodes
            .iter()
            .position(|(id, _)| id == relationship)
            .ok_or(EvidenceError::MissingRelationship)?;
        visit(nodes, next, path, depth + 1)?;
    }
    path.pop();
    Ok(())
}

fn validate_bytes(value: &[u8], field: &'static str) -> Result<(), EvidenceError> {
    if value.is_empty() || value.len() > MAX_EVIDENCE_TEXT_BYTES {
        Err(EvidenceError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), EvidenceError> {
    if value.is_empty()
        || value.len() > MAX_EVIDENCE_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(EvidenceError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}
fn push_text(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}
fn push_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            push_u64(out, value);
        }
        None => out.push(0),
    }
}
