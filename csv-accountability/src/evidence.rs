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
/// Stable registry identifier for a claim made in opposition to disclosed evidence.
pub const COUNTERCLAIM_REGISTRY_ID: &str = "org.diewan.evidence.counterclaim.v1";
/// Stable registry identifier for an explicit conflict between two evidence nodes.
pub const CONTRADICTION_REGISTRY_ID: &str = "org.diewan.evidence.contradiction.v1";
/// Stable registry identifier for a custody hand-off concerning disclosed evidence.
pub const CUSTODY_RECORD_REGISTRY_ID: &str = "org.diewan.evidence.custody-record.v1";

/// Reserved v0.2 registry identifiers; no v0.1 constructor accepts these.
pub const RESERVED_EVIDENCE_REGISTRY_IDS: &[&str] = &[
    "org.diewan.evidence.anchor.v1",
    "org.diewan.evidence.identity-binding.v1",
    "org.diewan.evidence.revocation-record.v1",
    "org.diewan.evidence.policy-snapshot.v1",
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

/// A protocol evidence meaning. Variants are distinct so conflicts and
/// provenance cannot be flattened into generic claims by consumers.
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
    /// A proposition made in opposition to one disclosed evidence node.
    Counterclaim {
        /// Evidence node whose proposition or observation is challenged.
        subject_evidence_id: EvidenceNodeId,
        /// Digest of the exact opposing proposition.
        proposition_digest: [u8; 32],
    },
    /// An explicit declaration that two disclosed nodes cannot both hold.
    Contradiction {
        /// First conflicting evidence node.
        left_evidence_id: EvidenceNodeId,
        /// Second conflicting evidence node.
        right_evidence_id: EvidenceNodeId,
        /// Digest of the exact conflict analysis retained as content.
        analysis_digest: [u8; 32],
    },
    /// A custody event for one disclosed evidence node.
    CustodyRecord {
        /// Evidence whose custody is recorded.
        subject_evidence_id: EvidenceNodeId,
        /// Previous custody record, absent only for the first disclosed event.
        previous_custody_id: Option<EvidenceNodeId>,
        /// Identity accepting custody at this event.
        custodian_identity: Vec<u8>,
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
            Self::Counterclaim { .. } => COUNTERCLAIM_REGISTRY_ID,
            Self::Contradiction { .. } => CONTRADICTION_REGISTRY_ID,
            Self::CustodyRecord { .. } => CUSTODY_RECORD_REGISTRY_ID,
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
    /// The graph contains the same content identifier more than once.
    DuplicateIdentifier,
    /// A typed relationship points to the wrong evidence meaning or subject.
    InvalidRelationshipSemantics,
    /// Canonical bytes are truncated, malformed, or use an unknown registry id.
    MalformedEncoding,
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
            EvidenceKind::Counterclaim {
                subject_evidence_id,
                proposition_digest,
            } => {
                if *proposition_digest == [0; 32]
                    || !self.relationships.contains(subject_evidence_id)
                {
                    return Err(EvidenceError::InvalidField("counterclaim"));
                }
            }
            EvidenceKind::Contradiction {
                left_evidence_id,
                right_evidence_id,
                analysis_digest,
            } => {
                if left_evidence_id == right_evidence_id
                    || *analysis_digest == [0; 32]
                    || !self.relationships.contains(left_evidence_id)
                    || !self.relationships.contains(right_evidence_id)
                {
                    return Err(EvidenceError::InvalidField("contradiction"));
                }
            }
            EvidenceKind::CustodyRecord {
                subject_evidence_id,
                previous_custody_id,
                custodian_identity,
            } => {
                validate_bytes(custodian_identity, "custodian_identity")?;
                if !self.relationships.contains(subject_evidence_id)
                    || previous_custody_id.is_some_and(|previous| {
                        previous == *subject_evidence_id || !self.relationships.contains(&previous)
                    })
                {
                    return Err(EvidenceError::InvalidField("custody_relationship"));
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
            EvidenceKind::Counterclaim {
                subject_evidence_id,
                proposition_digest,
            } => {
                out.extend_from_slice(subject_evidence_id.as_bytes());
                out.extend_from_slice(proposition_digest);
            }
            EvidenceKind::Contradiction {
                left_evidence_id,
                right_evidence_id,
                analysis_digest,
            } => {
                out.extend_from_slice(left_evidence_id.as_bytes());
                out.extend_from_slice(right_evidence_id.as_bytes());
                out.extend_from_slice(analysis_digest);
            }
            EvidenceKind::CustodyRecord {
                subject_evidence_id,
                previous_custody_id,
                custodian_identity,
            } => {
                out.extend_from_slice(subject_evidence_id.as_bytes());
                match previous_custody_id {
                    Some(previous) => {
                        out.push(1);
                        out.extend_from_slice(previous.as_bytes());
                    }
                    None => out.push(0),
                }
                push_bytes(&mut out, custodian_identity);
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

    /// Decodes one canonical evidence node and rejects trailing or non-canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let mut cursor = Cursor::new(bytes);
        let registry_id = cursor.text()?;
        let kind = match registry_id.as_str() {
            CLAIM_REGISTRY_ID => EvidenceKind::Claim {
                proposition_digest: cursor.array32()?,
            },
            OBSERVATION_REGISTRY_ID => EvidenceKind::Observation {
                method_id: cursor.text()?,
            },
            ATTESTATION_REGISTRY_ID => EvidenceKind::Attestation {
                attester_identity: cursor.bytes()?,
            },
            EVIDENCE_GAP_REGISTRY_ID => EvidenceKind::EvidenceGap {
                missing_registry_id: cursor.text()?,
                reason_digest: cursor.array32()?,
            },
            COUNTERCLAIM_REGISTRY_ID => EvidenceKind::Counterclaim {
                subject_evidence_id: EvidenceNodeId::from_digest(cursor.array32()?),
                proposition_digest: cursor.array32()?,
            },
            CONTRADICTION_REGISTRY_ID => EvidenceKind::Contradiction {
                left_evidence_id: EvidenceNodeId::from_digest(cursor.array32()?),
                right_evidence_id: EvidenceNodeId::from_digest(cursor.array32()?),
                analysis_digest: cursor.array32()?,
            },
            CUSTODY_RECORD_REGISTRY_ID => EvidenceKind::CustodyRecord {
                subject_evidence_id: EvidenceNodeId::from_digest(cursor.array32()?),
                previous_custody_id: match cursor.byte()? {
                    0 => None,
                    1 => Some(EvidenceNodeId::from_digest(cursor.array32()?)),
                    _ => return Err(EvidenceError::MalformedEncoding),
                },
                custodian_identity: cursor.bytes()?,
            },
            _ => return Err(EvidenceError::MalformedEncoding),
        };
        let producer_identity = cursor.bytes()?;
        let collected_at = cursor.u64()?;
        let asserted_event_at = match cursor.byte()? {
            0 => None,
            1 => Some(cursor.u64()?),
            _ => return Err(EvidenceError::MalformedEncoding),
        };
        let content_digest = cursor.array32()?;
        let media_type = cursor.text()?;
        let source_locator = match cursor.byte()? {
            0 => SourceLocator::Disclosed(cursor.text()?),
            1 => SourceLocator::Withheld(cursor.array32()?),
            _ => return Err(EvidenceError::MalformedEncoding),
        };
        let authenticity = match cursor.byte()? {
            0 => None,
            1 => Some(AuthenticityMaterial {
                scheme_id: cursor.text()?,
                material_digest: cursor.array32()?,
            }),
            _ => return Err(EvidenceError::MalformedEncoding),
        };
        let disclosure_classification = cursor.text()?;
        let relationship_count = cursor.u32()? as usize;
        if relationship_count > MAX_EVIDENCE_RELATIONSHIPS {
            return Err(EvidenceError::BoundsExceeded);
        }
        let mut relationships = Vec::with_capacity(relationship_count);
        for _ in 0..relationship_count {
            relationships.push(EvidenceNodeId::from_digest(cursor.array32()?));
        }
        if !cursor.is_empty() {
            return Err(EvidenceError::MalformedEncoding);
        }
        let node = Self {
            kind,
            producer_identity,
            collected_at,
            asserted_event_at,
            content_digest,
            media_type,
            source_locator,
            authenticity,
            disclosure_classification,
            relationships,
        };
        node.validate()?;
        if node.canonical_bytes()?.as_slice() != bytes {
            return Err(EvidenceError::MalformedEncoding);
        }
        Ok(node)
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
    for (index, (id, _)) in nodes.iter().enumerate() {
        if nodes[index + 1..]
            .iter()
            .any(|(candidate, _)| candidate == id)
        {
            return Err(EvidenceError::DuplicateIdentifier);
        }
    }
    // Check the supplied graph structure first so a cyclic hostile graph is
    // classified as a cycle rather than being masked by its necessarily
    // inconsistent content identifiers. Canonical identifier validation still
    // follows for every structurally valid graph.
    for index in 0..nodes.len() {
        let mut path = Vec::new();
        visit(nodes, index, &mut path, 0)?;
    }
    for (id, node) in nodes {
        if *id != node.id()? {
            return Err(EvidenceError::IdentifierMismatch);
        }
    }
    for (_, node) in nodes {
        if let EvidenceKind::CustodyRecord {
            subject_evidence_id,
            previous_custody_id: Some(previous_custody_id),
            ..
        } = &node.kind
        {
            let previous = nodes
                .iter()
                .find(|(id, _)| id == previous_custody_id)
                .map(|(_, node)| node)
                .ok_or(EvidenceError::MissingRelationship)?;
            if !matches!(
                &previous.kind,
                EvidenceKind::CustodyRecord {
                    subject_evidence_id: previous_subject,
                    ..
                } if previous_subject == subject_evidence_id
            ) {
                return Err(EvidenceError::InvalidRelationshipSemantics);
            }
        }
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

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], EvidenceError> {
        if len > self.remaining.len() {
            return Err(EvidenceError::MalformedEncoding);
        }
        let (value, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, EvidenceError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, EvidenceError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| EvidenceError::MalformedEncoding)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, EvidenceError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| EvidenceError::MalformedEncoding)?,
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], EvidenceError> {
        self.take(32)?
            .try_into()
            .map_err(|_| EvidenceError::MalformedEncoding)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, EvidenceError> {
        let len = self.u32()? as usize;
        if len > MAX_EVIDENCE_TEXT_BYTES {
            return Err(EvidenceError::BoundsExceeded);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn text(&mut self) -> Result<String, EvidenceError> {
        String::from_utf8(self.bytes()?).map_err(|_| EvidenceError::MalformedEncoding)
    }
}
