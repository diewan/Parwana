//! State transition DAG types
//!
//! The DAG represents deterministic state transitions verified off-chain.
//! Each node contains bytecode, witnesses, and validation data.
//!
//! # Canonical identity (PAR-DAG-001)
//!
//! A node's identity is **recomputed from its canonical contents**; a supplied
//! identifier is never trusted. A segment's root commitment is likewise
//! recomputed from the canonical node set. Mutating node content or
//! substituting a root therefore invalidates the segment
//! ([`DAGSegment::validate_structure`]).
//!
//! Node, edge, content, and root digests each use a distinct domain tag, so a
//! digest computed for one position can never be presented in another
//! (RFC-0014 §3.1 P2; threat T-NE-05 rules `NE-R-NODE-ID-RECOMPUTED`,
//! `NE-R-ROOT-RECOMPUTED`, `NE-R-DOMAIN-SEPARATED`).
//!
//! # Structural validation (PAR-DAG-002)
//!
//! Validation rejects hostile graphs with distinct, machine-readable errors
//! rather than accepting anything that decodes: empty segments, duplicate
//! identifiers, self-parenting, duplicate or missing parents, cycles, and
//! non-canonically-ordered node lists (rules `NE-R-NODE-ID-UNIQUE`,
//! `NE-R-ACYCLIC`, `NE-R-PARENTS-RESOLVE`, `NE-R-CANONICAL-ORDER`).
//!
//! Multiple roots and disconnected components are permitted — a segment may
//! carry parallel histories — provided every declared parent resolves inside
//! the segment, so ancestry terminates there (`NE-R-ROOTS-DEFINED`).
//!
//! Construct segments with [`DAGSegment::sealed`], which canonicalizes order
//! and computes the root. [`DAGSegment::new`] and [`DAGNode::new`] remain
//! unchecked so that decoders and adversarial tests can build the hostile
//! inputs validation must reject.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::Hash;
use crate::csv_tagged_hash;
use csv_codec::{CanonicalEncoding, EncodingFormat};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Domain tag for a node's content digest (bytecode, signatures, witnesses).
pub const DAG_CONTENT_TAG: &str = "dag-content-v2";
/// Domain tag for a node's edge digest (its ordered parent references).
pub const DAG_EDGE_TAG: &str = "dag-edge-v2";
/// Domain tag for a node's canonical identity.
pub const DAG_NODE_TAG: &str = "dag-node-v2";
/// Domain tag for a segment's root commitment.
pub const DAG_ROOT_TAG: &str = "dag-root-v2";

/// A machine-readable reason a DAG segment is not canonical or not well-formed.
///
/// Each variant is a distinct rejection reason. Callers and conformance vectors
/// depend on them being distinguishable: "the bundle is invalid" is not an
/// acceptable answer to "which hostile property did it have?".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DagStructureError {
    /// The segment carries no nodes. An empty graph asserts nothing and is
    /// never a valid transition history.
    EmptySegment,
    /// Two nodes share an identifier, so a parent reference is ambiguous.
    DuplicateNodeId {
        /// The repeated identifier.
        node: Hash,
    },
    /// A node's declared identifier is not the identifier its contents produce.
    /// This is what mutated node content looks like.
    NodeIdMismatch {
        /// The identifier the node declared.
        declared: Hash,
        /// The identifier its canonical contents produce.
        recomputed: Hash,
    },
    /// A node lists itself as its own parent.
    SelfParent {
        /// The offending node.
        node: Hash,
    },
    /// A node lists the same parent more than once, making ancestry ambiguous.
    DuplicateParent {
        /// The offending node.
        node: Hash,
        /// The repeated parent.
        parent: Hash,
    },
    /// A node references a parent that is not present in the segment.
    MissingParent {
        /// The offending node.
        node: Hash,
        /// The parent that does not resolve.
        parent: Hash,
    },
    /// The parent relation contains a cycle, so no topological order exists.
    Cycle {
        /// One node that remains unresolvable after the topological sort.
        node: Hash,
    },
    /// The segment has no root node. A nonempty acyclic graph always has one,
    /// so this reports a graph that is cyclic in a way the sort did not reach.
    NoRoot,
    /// Nodes are not stored in canonical (topological, id-ascending) order.
    /// The graph is rejected rather than silently re-identified.
    NonCanonicalOrder {
        /// Index at which the declared order first diverges.
        position: usize,
        /// The identifier canonical order requires at that index.
        expected: Hash,
        /// The identifier found there.
        found: Hash,
    },
    /// The declared root commitment is not the one the canonical node set
    /// produces. This is what a substituted root looks like.
    RootMismatch {
        /// The root the segment declared.
        declared: Hash,
        /// The root its canonical node set produces.
        recomputed: Hash,
    },
}

impl fmt::Display for DagStructureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySegment => write!(f, "DAG segment is empty"),
            Self::DuplicateNodeId { node } => {
                write!(f, "duplicate node identifier {node}")
            }
            Self::NodeIdMismatch {
                declared,
                recomputed,
            } => write!(
                f,
                "node identifier {declared} does not match its canonical contents {recomputed}"
            ),
            Self::SelfParent { node } => write!(f, "node {node} lists itself as parent"),
            Self::DuplicateParent { node, parent } => {
                write!(f, "node {node} lists parent {parent} more than once")
            }
            Self::MissingParent { node, parent } => {
                write!(f, "node {node} references absent parent {parent}")
            }
            Self::Cycle { node } => write!(f, "DAG contains a cycle through node {node}"),
            Self::NoRoot => write!(f, "DAG segment has no root node"),
            Self::NonCanonicalOrder {
                position,
                expected,
                found,
            } => write!(
                f,
                "non-canonical node order at index {position}: expected {expected}, found {found}"
            ),
            Self::RootMismatch {
                declared,
                recomputed,
            } => write!(
                f,
                "root commitment {declared} does not match the canonical node set {recomputed}"
            ),
        }
    }
}

impl std::error::Error for DagStructureError {}

/// A single node in the state transition DAG
/// L0 type: uses canonical_cbor for serialization (manual implementation)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DAGNode {
    /// Unique identifier for this node
    pub node_id: Hash,
    /// Deterministic VM bytecode (e.g., AluVM)
    pub bytecode: Vec<u8>,
    /// Authorizing signatures
    pub signatures: Vec<Vec<u8>>,
    /// Witness data for verification
    pub witnesses: Vec<Vec<u8>>,
    /// Hash of parent node(s) - empty for root
    pub parents: Vec<Hash>,
}

impl CanonicalEncoding for DAGNode {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => Ok(self.to_canonical_bytes()),
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_canonical_bytes(bytes)
                .map_err(|e| csv_codec::CodecError::DeserializationError(e.to_string())),
        }
    }
}

impl DAGNode {
    /// Create a DAG node from an explicit identifier, **without checking it**.
    ///
    /// The identifier is stored as declared. Use [`DAGNode::sealed`] to build a
    /// node whose identity is derived from its contents; this constructor
    /// exists so decoders and adversarial tests can construct the mismatched
    /// nodes [`DAGSegment::validate_structure`] must reject.
    pub fn new(
        node_id: Hash,
        bytecode: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        witnesses: Vec<Vec<u8>>,
        parents: Vec<Hash>,
    ) -> Self {
        Self {
            node_id,
            bytecode,
            signatures,
            witnesses,
            parents,
        }
    }

    /// Create a DAG node whose identifier is derived from its canonical
    /// contents (PAR-DAG-001).
    ///
    /// This is the production constructor. There is no way to choose the
    /// identifier: it is a function of what the node says.
    pub fn sealed(
        bytecode: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        witnesses: Vec<Vec<u8>>,
        parents: Vec<Hash>,
    ) -> Self {
        let mut node = Self {
            node_id: Hash::zero(),
            bytecode,
            signatures,
            witnesses,
            parents,
        };
        node.node_id = node.canonical_id();
        node
    }

    /// Digest of the node's payload: bytecode, signatures, and witnesses.
    ///
    /// Excludes the declared identifier (which is derived from this) and the
    /// parent references (which are separately domain-separated as edges).
    pub fn content_digest(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&(self.bytecode.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.bytecode);
        data.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            data.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            data.extend_from_slice(sig);
        }
        data.extend_from_slice(&(self.witnesses.len() as u32).to_le_bytes());
        for wit in &self.witnesses {
            data.extend_from_slice(&(wit.len() as u32).to_le_bytes());
            data.extend_from_slice(wit);
        }
        Hash::new(csv_tagged_hash(DAG_CONTENT_TAG, &data))
    }

    /// Digest of the node's ordered parent references.
    ///
    /// Carries its own domain tag so an edge digest can never be presented as a
    /// node identity or a segment root.
    pub fn edge_digest(&self) -> Hash {
        let mut data = Vec::with_capacity(4 + self.parents.len() * 32);
        data.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for parent in &self.parents {
            data.extend_from_slice(parent.as_bytes());
        }
        Hash::new(csv_tagged_hash(DAG_EDGE_TAG, &data))
    }

    /// The identifier this node's canonical contents produce (PAR-DAG-001).
    ///
    /// `node_id = H_node(H_content(payload) || H_edge(parents))`, each digest
    /// under its own domain tag. Changing any byte of the payload, or any
    /// parent reference or their order, changes the identifier.
    pub fn canonical_id(&self) -> Hash {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(self.content_digest().as_bytes());
        data.extend_from_slice(self.edge_digest().as_bytes());
        Hash::new(csv_tagged_hash(DAG_NODE_TAG, &data))
    }

    /// Check that the declared identifier is the one the contents produce.
    pub fn verify_identity(&self) -> Result<(), DagStructureError> {
        let recomputed = self.canonical_id();
        if self.node_id == recomputed {
            Ok(())
        } else {
            Err(DagStructureError::NodeIdMismatch {
                declared: self.node_id,
                recomputed,
            })
        }
    }

    /// The node's canonical identity.
    ///
    /// Identical to [`DAGNode::canonical_id`]: a node's hash *is* its identity.
    /// Before PAR-DAG-001 this mixed the declared identifier into the preimage,
    /// which let a caller pick a value that no content check could contradict.
    pub fn hash(&self) -> Hash {
        self.canonical_id()
    }

    /// Serialize to canonical bytes (manual implementation for L0 type)
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.node_id.as_bytes());
        data.extend_from_slice(&(self.bytecode.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.bytecode);
        data.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            data.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            data.extend_from_slice(sig);
        }
        data.extend_from_slice(&(self.witnesses.len() as u32).to_le_bytes());
        for wit in &self.witnesses {
            data.extend_from_slice(&(wit.len() as u32).to_le_bytes());
            data.extend_from_slice(wit);
        }
        data.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for parent in &self.parents {
            data.extend_from_slice(parent.as_bytes());
        }
        data
    }

    /// Deserialize from canonical bytes (manual implementation for L0 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;

        let node_id = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash::new(hash)
        } else {
            return Err("Insufficient bytes for node_id");
        };

        let bytecode_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for bytecode length");
        };

        let bytecode = if bytes.len() >= pos + bytecode_len {
            let data = bytes[pos..pos + bytecode_len].to_vec();
            pos += bytecode_len;
            data
        } else {
            return Err("Insufficient bytes for bytecode");
        };

        let signatures_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for signatures length");
        };

        let mut signatures = Vec::with_capacity(signatures_len);
        for _ in 0..signatures_len {
            let sig_len = if bytes.len() >= pos + 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes[pos..pos + 4]);
                let len = u32::from_le_bytes(arr) as usize;
                pos += 4;
                len
            } else {
                return Err("Insufficient bytes for signature length");
            };
            let sig = if bytes.len() >= pos + sig_len {
                let data = bytes[pos..pos + sig_len].to_vec();
                pos += sig_len;
                data
            } else {
                return Err("Insufficient bytes for signature");
            };
            signatures.push(sig);
        }

        let witnesses_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for witnesses length");
        };

        let mut witnesses = Vec::with_capacity(witnesses_len);
        for _ in 0..witnesses_len {
            let witness_len = if bytes.len() >= pos + 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes[pos..pos + 4]);
                let len = u32::from_le_bytes(arr) as usize;
                pos += 4;
                len
            } else {
                return Err("Insufficient bytes for witness length");
            };
            let witness = if bytes.len() >= pos + witness_len {
                let data = bytes[pos..pos + witness_len].to_vec();
                pos += witness_len;
                data
            } else {
                return Err("Insufficient bytes for witness");
            };
            witnesses.push(witness);
        }

        let parents_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for parents length");
        };

        let mut parents = Vec::with_capacity(parents_len);
        for _ in 0..parents_len {
            if bytes.len() >= pos + 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[pos..pos + 32]);
                pos += 32;
                parents.push(Hash::new(hash));
            } else {
                return Err("Insufficient bytes for parent hash");
            }
        }

        Ok(Self {
            node_id,
            bytecode,
            signatures,
            witnesses,
            parents,
        })
    }
}

/// A segment of the state transition DAG
/// L0 type: uses manual canonical_cbor serialization
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DAGSegment {
    /// Nodes in this segment
    pub nodes: Vec<DAGNode>,
    /// Root commitment hash
    pub root_commitment: Hash,
}

impl CanonicalEncoding for DAGSegment {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => Ok(self.to_canonical_bytes()),
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_canonical_bytes(bytes)
                .map_err(|e| csv_codec::CodecError::DeserializationError(e.to_string())),
        }
    }
}

impl DAGSegment {
    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for node in &self.nodes {
            let node_bytes = node.encode_mce()?;
            data.extend_from_slice(&(node_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&node_bytes);
        }
        data.extend_from_slice(self.root_commitment.as_bytes());
        Ok(data)
    }

    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        let mut pos = 0;

        let nodes_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for nodes length".to_string(),
            ));
        };

        let mut nodes = Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            let node_len = if bytes.len() >= pos + 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes[pos..pos + 4]);
                let len = u32::from_le_bytes(arr) as usize;
                pos += 4;
                len
            } else {
                return Err(csv_codec::CodecError::DeserializationError(
                    "Insufficient bytes for node length".to_string(),
                ));
            };
            let node = if bytes.len() >= pos + node_len {
                let node_bytes = &bytes[pos..pos + node_len];
                pos += node_len;
                DAGNode::decode_mce(node_bytes)?
            } else {
                return Err(csv_codec::CodecError::DeserializationError(
                    "Insufficient bytes for node data".to_string(),
                ));
            };
            nodes.push(node);
        }

        let root_commitment = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash::new(hash)
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for root commitment".to_string(),
            ));
        };

        Ok(Self {
            nodes,
            root_commitment,
        })
    }

    /// Create a DAG segment from an explicit root commitment, **without
    /// checking it**.
    ///
    /// Use [`DAGSegment::sealed`] to build a segment whose root is derived from
    /// its nodes; this constructor exists so decoders and adversarial tests can
    /// construct the substituted roots
    /// [`DAGSegment::validate_structure`] must reject.
    pub fn new(nodes: Vec<DAGNode>, root_commitment: Hash) -> Self {
        Self {
            nodes,
            root_commitment,
        }
    }

    /// Build a canonical segment: order the nodes, derive each identifier from
    /// its contents, and compute the root commitment (PAR-DAG-001/002).
    ///
    /// This is the production constructor. The caller supplies node contents
    /// and ancestry; it cannot choose identifiers, order, or root.
    ///
    /// Parents are given as declared. If the caller built its nodes with
    /// [`DAGNode::sealed`], those references are already canonical identifiers.
    pub fn sealed(nodes: Vec<DAGNode>) -> Result<Self, DagStructureError> {
        if nodes.is_empty() {
            return Err(DagStructureError::EmptySegment);
        }
        let nodes: Vec<DAGNode> = nodes
            .into_iter()
            .map(|node| {
                DAGNode::sealed(node.bytecode, node.signatures, node.witnesses, node.parents)
            })
            .collect();

        // Resolve ancestry before ordering, so a caller that passed parent
        // references from unsealed nodes gets `MissingParent` rather than the
        // `Cycle` an unresolvable parent would otherwise look like.
        let present: BTreeSet<Hash> = nodes.iter().map(|node| node.node_id).collect();
        for node in &nodes {
            for parent in &node.parents {
                if !present.contains(parent) {
                    return Err(DagStructureError::MissingParent {
                        node: node.node_id,
                        parent: *parent,
                    });
                }
            }
        }

        let order = topological_order(&nodes)?;
        let ordered: Vec<DAGNode> = order.iter().map(|index| nodes[*index].clone()).collect();

        let root_commitment = root_of_nodes(&ordered, &(0..ordered.len()).collect::<Vec<_>>());
        let segment = Self {
            nodes: ordered,
            root_commitment,
        };
        segment.validate_structure()?;
        Ok(segment)
    }

    /// The canonical order of this segment's node identifiers.
    ///
    /// Topological by the parent relation, with ties broken by ascending
    /// identifier, so one graph has exactly one order regardless of how its
    /// nodes were listed.
    ///
    /// Checks the relation rules first, so an ambiguous graph reports the
    /// property that made it ambiguous rather than an order derived from it: an
    /// order over duplicate identifiers or unresolvable parents would be an
    /// answer to a question the segment does not well-pose.
    pub fn canonical_order(&self) -> Result<Vec<Hash>, DagStructureError> {
        Ok(self
            .checked_order()?
            .into_iter()
            .map(|index| self.nodes[index].node_id)
            .collect())
    }

    /// The root commitment this segment's canonical node set produces
    /// (PAR-DAG-001).
    ///
    /// Committed over each node's **recomputed** identity, in canonical order,
    /// under the root domain tag. Recomputing rather than reusing the declared
    /// identifiers is what makes a content mutation visible here even when the
    /// attacker leaves the stale identifier in place.
    ///
    /// A segment whose relation rules fail has no canonical root: it reports
    /// the failure instead of a value a caller could compare against.
    pub fn canonical_root(&self) -> Result<Hash, DagStructureError> {
        let order = self.checked_order()?;
        Ok(root_of_nodes(&self.nodes, &order))
    }

    /// Validate every rule that does **not** depend on recomputing node
    /// identity: the segment is nonempty, identifiers are unique, no node
    /// parents itself, repeats a parent, or references an absent one, the
    /// parent relation is acyclic, and ancestry terminates at a root
    /// (`NE-R-NODE-ID-UNIQUE`, `NE-R-ACYCLIC`, `NE-R-PARENTS-RESOLVE`,
    /// `NE-R-ROOTS-DEFINED`).
    ///
    /// These rules read the *declared* identifiers, so they hold for a segment
    /// whose identifiers were supplied rather than derived. That matters on the
    /// runtime path, where a chain adapter still selects node identifiers and
    /// the segment root: identity cannot be recomputed there yet, but a cycle,
    /// a duplicate identifier or an unresolvable parent is a defect on any
    /// path, and reporting it as merely unknown would downgrade a structural
    /// failure to an uncertainty.
    ///
    /// [`DAGSegment::validate_structure`] is this plus the identity rules
    /// (`NE-R-NODE-ID-RECOMPUTED`, `NE-R-CANONICAL-ORDER`,
    /// `NE-R-ROOT-RECOMPUTED`) and is what a fully canonical segment must pass.
    pub fn validate_relations(&self) -> Result<(), DagStructureError> {
        self.checked_order().map(|_| ())
    }

    /// Identifier uniqueness and well-formed ancestry — the preconditions that
    /// make a topological order meaningful (`NE-R-NODE-ID-UNIQUE`,
    /// `NE-R-ACYCLIC` self-parent arm, `NE-R-PARENTS-RESOLVE`).
    ///
    /// Deliberately excludes identity recomputation: a caller asking for the
    /// canonical order or root of a mutated segment must still get an answer to
    /// compare against, which is how a content mutation is caught.
    fn check_relations(&self) -> Result<(), DagStructureError> {
        if self.nodes.is_empty() {
            return Err(DagStructureError::EmptySegment);
        }

        let mut node_ids = BTreeSet::new();
        for node in &self.nodes {
            if !node_ids.insert(node.node_id) {
                return Err(DagStructureError::DuplicateNodeId { node: node.node_id });
            }
        }

        for node in &self.nodes {
            let mut seen_parents = BTreeSet::new();
            for parent in &node.parents {
                if *parent == node.node_id {
                    return Err(DagStructureError::SelfParent { node: node.node_id });
                }
                if !seen_parents.insert(*parent) {
                    return Err(DagStructureError::DuplicateParent {
                        node: node.node_id,
                        parent: *parent,
                    });
                }
                if !node_ids.contains(parent) {
                    return Err(DagStructureError::MissingParent {
                        node: node.node_id,
                        parent: *parent,
                    });
                }
            }
        }

        Ok(())
    }

    /// The canonical order, with the relation rules and the root rule checked.
    ///
    /// A nonempty segment whose parents resolve and whose relation is acyclic
    /// always has at least one parentless node, so [`DagStructureError::NoRoot`]
    /// is not reachable from a graph that got this far. It is checked rather
    /// than assumed: this is the one place that decides ancestry terminates, and
    /// a graph that somehow reached it with nothing to start from must fail
    /// closed rather than be committed to a root.
    fn checked_order(&self) -> Result<Vec<usize>, DagStructureError> {
        self.check_relations()?;
        let order = topological_order(&self.nodes)?;
        if self.roots().is_empty() {
            return Err(DagStructureError::NoRoot);
        }
        Ok(order)
    }

    /// The segment's root nodes: those declaring no parents.
    ///
    /// Multiple roots are permitted — a segment may carry parallel histories —
    /// and so are disconnected components, provided every node's ancestry
    /// resolves inside the segment (`NE-R-ROOTS-DEFINED`). A nonempty acyclic
    /// segment whose parents resolve always has at least one root;
    /// [`DagStructureError::NoRoot`] is the fail-closed answer for a graph that
    /// reaches the ordering step without one.
    pub fn roots(&self) -> Vec<Hash> {
        self.nodes
            .iter()
            .filter(|node| node.parents.is_empty())
            .map(|node| node.node_id)
            .collect()
    }

    /// Serialize to canonical bytes (manual implementation for L0 type)
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for node in &self.nodes {
            let node_bytes = node.to_canonical_bytes();
            data.extend_from_slice(&(node_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&node_bytes);
        }
        data.extend_from_slice(self.root_commitment.as_bytes());
        data
    }

    /// Deserialize from canonical bytes (manual implementation for L0 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;

        let nodes_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for nodes length");
        };

        let mut nodes = Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            let node_len = if bytes.len() >= pos + 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes[pos..pos + 4]);
                let len = u32::from_le_bytes(arr) as usize;
                pos += 4;
                len
            } else {
                return Err("Insufficient bytes for node length");
            };
            let node = if bytes.len() >= pos + node_len {
                let node_bytes = &bytes[pos..pos + node_len];
                pos += node_len;
                DAGNode::from_canonical_bytes(node_bytes)?
            } else {
                return Err("Insufficient bytes for node");
            };
            nodes.push(node);
        }

        let root_commitment = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash::new(hash)
        } else {
            return Err("Insufficient bytes for root_commitment");
        };

        Ok(Self {
            nodes,
            root_commitment,
        })
    }

    /// Validate the segment against every canonical-identity and structural
    /// rule (PAR-DAG-001, PAR-DAG-002).
    ///
    /// Checks are ordered so that each hostile property reports its own
    /// [`DagStructureError`] variant rather than being masked by a later,
    /// broader one:
    ///
    /// 1. the segment is nonempty;
    /// 2. identifiers are unique;
    /// 3. no node parents itself, repeats a parent, or references an absent one;
    /// 4. the parent relation is acyclic and has at least one root;
    /// 5. every identifier is the one its contents produce;
    /// 6. nodes are stored in canonical order;
    /// 7. the root commitment is the one the canonical node set produces.
    pub fn validate_structure(&self) -> Result<(), DagStructureError> {
        // Acyclicity is checked before identity: a cyclic graph must report
        // `Cycle`, not the identifier mismatch that a hand-built cycle
        // necessarily also has. (A cycle among content-derived identifiers
        // would require a hash cycle, so the two never co-occur honestly.)
        let order = self.checked_order()?;

        for node in &self.nodes {
            node.verify_identity()?;
        }

        for (position, index) in order.iter().enumerate() {
            let expected = self.nodes[*index].node_id;
            let found = self.nodes[position].node_id;
            if found != expected {
                return Err(DagStructureError::NonCanonicalOrder {
                    position,
                    expected,
                    found,
                });
            }
        }

        let recomputed = root_of_nodes(&self.nodes, &order);
        if self.root_commitment != recomputed {
            return Err(DagStructureError::RootMismatch {
                declared: self.root_commitment,
                recomputed,
            });
        }

        Ok(())
    }
}

/// Commit to the recomputed identities of `nodes`, visited in `order`, under
/// the root domain tag.
fn root_of_nodes(nodes: &[DAGNode], order: &[usize]) -> Hash {
    let mut data = Vec::with_capacity(4 + order.len() * 32);
    data.extend_from_slice(&(order.len() as u32).to_le_bytes());
    for index in order {
        data.extend_from_slice(nodes[*index].canonical_id().as_bytes());
    }
    Hash::new(csv_tagged_hash(DAG_ROOT_TAG, &data))
}

/// Commit to an ordered list of node identifiers under the root domain tag.
///
/// Exposed for canonical vectors and cross-implementation checks that need the
/// root of an identifier list directly. Production validation goes through
/// [`DAGSegment::canonical_root`], which recomputes each identifier from its
/// node rather than trusting the list.
pub fn root_of(order: &[Hash]) -> Hash {
    let mut data = Vec::with_capacity(4 + order.len() * 32);
    data.extend_from_slice(&(order.len() as u32).to_le_bytes());
    for id in order {
        data.extend_from_slice(id.as_bytes());
    }
    Hash::new(csv_tagged_hash(DAG_ROOT_TAG, &data))
}

/// Kahn's algorithm with an ascending-identifier tie-break, returning indices
/// into `nodes`.
///
/// Selecting the smallest available identifier at each step makes the order a
/// function of the graph alone: two segments listing the same nodes in
/// different orders produce the same sequence, so they cannot be accepted under
/// two different identities.
///
/// Identifiers are assumed unique and parents assumed to resolve. Both are
/// preconditions, not properties this function re-establishes:
/// [`DAGSegment::check_relations`] runs first on every path that reaches here
/// ([`DAGSegment::checked_order`] and [`DAGSegment::sealed`]) and reports the
/// specific error.
///
/// The preconditions are load-bearing. `pending` counts only the parents that
/// *resolve*, so a node whose parents are all absent has a pending count of
/// zero and is ordered immediately rather than being held back — an
/// unresolvable parent is ignored here, not detected. Keep this function
/// private and keep the relation check ahead of it; a caller that skipped it
/// would silently order a graph whose ancestry does not close.
fn topological_order(nodes: &[DAGNode]) -> Result<Vec<usize>, DagStructureError> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }

    // First occurrence wins; duplicate identifiers are rejected before this.
    let mut index_of: BTreeMap<Hash, usize> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        index_of.entry(node.node_id).or_insert(index);
    }

    // Remaining parent count per node, and the children each parent unblocks.
    let mut pending: Vec<usize> = Vec::with_capacity(nodes.len());
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        let mut resolvable = 0usize;
        for parent in &node.parents {
            if let Some(parent_index) = index_of.get(parent) {
                resolvable += 1;
                children[*parent_index].push(index);
            }
        }
        pending.push(resolvable);
    }

    // Ordered by identifier, then index, so selection is deterministic even if
    // two nodes somehow share an identifier.
    let mut ready: BTreeSet<(Hash, usize)> = pending
        .iter()
        .enumerate()
        .filter(|(_, count)| **count == 0)
        .map(|(index, _)| (nodes[index].node_id, index))
        .collect();

    let smallest = |candidates: &[usize]| -> Hash {
        candidates
            .iter()
            .map(|index| nodes[*index].node_id)
            .min()
            .unwrap_or_else(Hash::zero)
    };

    if ready.is_empty() {
        // Nonempty, but nothing has zero resolvable parents: every node is in
        // or behind a cycle.
        let all: Vec<usize> = (0..nodes.len()).collect();
        return Err(DagStructureError::Cycle {
            node: smallest(&all),
        });
    }

    let mut order = Vec::with_capacity(nodes.len());
    while let Some((_, index)) = ready.iter().next().copied() {
        ready.remove(&(nodes[index].node_id, index));
        order.push(index);
        for child in &children[index] {
            pending[*child] = pending[*child].saturating_sub(1);
            if pending[*child] == 0 {
                ready.insert((nodes[*child].node_id, *child));
            }
        }
    }

    if order.len() != nodes.len() {
        let stuck: Vec<usize> = (0..nodes.len())
            .filter(|index| !order.contains(index))
            .collect();
        return Err(DagStructureError::Cycle {
            node: smallest(&stuck),
        });
    }

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────

    /// A sealed node with no ancestry.
    fn root_node(tag: u8) -> DAGNode {
        DAGNode::sealed(vec![tag], vec![], vec![], vec![])
    }

    /// A sealed node with the given ancestry.
    fn child_node(tag: u8, parents: Vec<Hash>) -> DAGNode {
        DAGNode::sealed(vec![tag], vec![], vec![], parents)
    }

    /// root → child, canonical.
    fn simple_chain() -> DAGSegment {
        let root = root_node(1);
        let child = child_node(2, vec![root.node_id]);
        DAGSegment::sealed(vec![root, child]).expect("canonical chain")
    }

    // ─────────────────────────────────────────────
    // Node identity (PAR-DAG-001)
    // ─────────────────────────────────────────────

    #[test]
    fn sealed_node_identity_is_derived_from_contents() {
        let node = DAGNode::sealed(vec![0x01, 0x02], vec![vec![0xAB; 64]], vec![], vec![]);
        assert_eq!(node.node_id, node.canonical_id());
        assert!(node.verify_identity().is_ok());
    }

    #[test]
    fn node_identity_is_deterministic() {
        let a = DAGNode::sealed(vec![0x01], vec![vec![0xAB; 8]], vec![vec![0xCD; 4]], vec![]);
        let b = DAGNode::sealed(vec![0x01], vec![vec![0xAB; 8]], vec![vec![0xCD; 4]], vec![]);
        assert_eq!(a.node_id, b.node_id);
    }

    #[test]
    fn node_identity_changes_with_every_content_field() {
        let base = DAGNode::sealed(vec![0x01], vec![vec![0xAA; 8]], vec![vec![0xBB; 8]], vec![]);
        let parent = Hash::new([7u8; 32]);

        let by_bytecode =
            DAGNode::sealed(vec![0x02], vec![vec![0xAA; 8]], vec![vec![0xBB; 8]], vec![]);
        let by_signature =
            DAGNode::sealed(vec![0x01], vec![vec![0xCC; 8]], vec![vec![0xBB; 8]], vec![]);
        let by_witness =
            DAGNode::sealed(vec![0x01], vec![vec![0xAA; 8]], vec![vec![0xDD; 8]], vec![]);
        let by_parent = DAGNode::sealed(
            vec![0x01],
            vec![vec![0xAA; 8]],
            vec![vec![0xBB; 8]],
            vec![parent],
        );

        for other in [&by_bytecode, &by_signature, &by_witness, &by_parent] {
            assert_ne!(base.node_id, other.node_id);
        }
    }

    #[test]
    fn node_identity_is_order_sensitive() {
        let sigs_ab = DAGNode::sealed(vec![], vec![vec![0xAA; 4], vec![0xBB; 4]], vec![], vec![]);
        let sigs_ba = DAGNode::sealed(vec![], vec![vec![0xBB; 4], vec![0xAA; 4]], vec![], vec![]);
        assert_ne!(sigs_ab.node_id, sigs_ba.node_id);

        let p1 = Hash::new([10u8; 32]);
        let p2 = Hash::new([20u8; 32]);
        let parents_12 = DAGNode::sealed(vec![], vec![], vec![], vec![p1, p2]);
        let parents_21 = DAGNode::sealed(vec![], vec![], vec![], vec![p2, p1]);
        assert_ne!(parents_12.node_id, parents_21.node_id);
    }

    #[test]
    fn node_identity_cannot_be_chosen_by_the_caller() {
        // The pre-PAR-DAG-001 shape: an identifier picked out of the air.
        let node = DAGNode::new(Hash::new([1u8; 32]), vec![0x01], vec![], vec![], vec![]);
        assert_eq!(
            node.verify_identity(),
            Err(DagStructureError::NodeIdMismatch {
                declared: Hash::new([1u8; 32]),
                recomputed: node.canonical_id(),
            })
        );
    }

    // ─────────────────────────────────────────────
    // Domain separation (PAR-DAG-001)
    // ─────────────────────────────────────────────

    #[test]
    fn node_edge_content_and_root_tags_are_distinct() {
        let tags = [DAG_CONTENT_TAG, DAG_EDGE_TAG, DAG_NODE_TAG, DAG_ROOT_TAG];
        let unique: BTreeSet<&str> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len(), "domain tags must be distinct");
    }

    #[test]
    fn one_payload_hashes_differently_in_every_domain() {
        // The property that stops a digest computed for one position being
        // presented in another.
        let payload = b"identical payload";
        let digests: BTreeSet<[u8; 32]> =
            [DAG_CONTENT_TAG, DAG_EDGE_TAG, DAG_NODE_TAG, DAG_ROOT_TAG]
                .iter()
                .map(|tag| csv_tagged_hash(tag, payload))
                .collect();
        assert_eq!(digests.len(), 4);
    }

    #[test]
    fn a_node_id_is_not_reusable_as_its_own_edge_or_root_digest() {
        let node = DAGNode::sealed(vec![0x01], vec![], vec![], vec![Hash::new([9u8; 32])]);
        let segment_root = root_of(&[node.node_id]);
        assert_ne!(node.node_id, node.edge_digest());
        assert_ne!(node.node_id, node.content_digest());
        assert_ne!(node.node_id, segment_root);
        assert_ne!(node.edge_digest(), segment_root);
    }

    // ─────────────────────────────────────────────
    // Segment root (PAR-DAG-001)
    // ─────────────────────────────────────────────

    #[test]
    fn sealed_segment_root_is_recomputed() {
        let segment = simple_chain();
        assert_eq!(
            segment.root_commitment,
            segment.canonical_root().expect("acyclic")
        );
        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn mutating_node_content_invalidates_the_segment() {
        let mut segment = simple_chain();
        segment.nodes[0].bytecode = vec![0xFF];
        // The declared identifier no longer matches its contents.
        assert!(matches!(
            segment.validate_structure(),
            Err(DagStructureError::NodeIdMismatch { .. })
        ));
    }

    #[test]
    fn mutating_node_content_and_its_identifier_still_invalidates_the_root() {
        let mut segment = simple_chain();
        // A more careful attacker also fixes up the identifier — but the root
        // commits to the node set, so the substitution is still visible.
        segment.nodes[0] = DAGNode::sealed(vec![0xFF], vec![], vec![], vec![]);
        let failure = segment.validate_structure().expect_err("must reject");
        assert!(
            matches!(
                failure,
                DagStructureError::MissingParent { .. }
                    | DagStructureError::RootMismatch { .. }
                    | DagStructureError::NonCanonicalOrder { .. }
            ),
            "unexpected failure: {failure}"
        );
    }

    #[test]
    fn substituting_the_root_invalidates_the_segment() {
        let mut segment = simple_chain();
        let declared = Hash::new([42u8; 32]);
        segment.root_commitment = declared;
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::RootMismatch {
                declared,
                recomputed: segment.canonical_root().unwrap(),
            })
        );
    }

    #[test]
    fn the_root_depends_on_the_whole_node_set() {
        let one = DAGSegment::sealed(vec![root_node(1)]).unwrap();
        let two = DAGSegment::sealed(vec![root_node(1), root_node(2)]).unwrap();
        assert_ne!(one.root_commitment, two.root_commitment);
    }

    // ─────────────────────────────────────────────
    // Structural validation (PAR-DAG-002)
    // ─────────────────────────────────────────────

    #[test]
    fn empty_segment_is_rejected() {
        let segment = DAGSegment::new(vec![], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::EmptySegment)
        );
        assert_eq!(
            DAGSegment::sealed(vec![]),
            Err(DagStructureError::EmptySegment)
        );
    }

    #[test]
    fn duplicate_node_identifiers_are_rejected() {
        let node = root_node(1);
        let segment = DAGSegment::new(vec![node.clone(), node.clone()], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::DuplicateNodeId { node: node.node_id })
        );
    }

    #[test]
    fn a_self_parenting_node_cannot_be_sealed() {
        // Sealing derives the identifier from the contents, so a node cannot
        // name an identifier it does not yet have. The attempt fails as an
        // unresolvable parent rather than silently producing a valid-looking
        // self-loop.
        let placeholder = Hash::new([7u8; 32]);
        let node = DAGNode::sealed(vec![0x01], vec![], vec![], vec![placeholder]);
        assert_eq!(
            DAGSegment::sealed(vec![node.clone()]),
            Err(DagStructureError::MissingParent {
                node: node.node_id,
                parent: placeholder,
            })
        );
    }

    #[test]
    fn a_node_naming_itself_reports_self_parent() {
        // Construct the exact hostile shape: declared id == declared parent.
        let id = Hash::new([5u8; 32]);
        let node = DAGNode::new(id, vec![0x01], vec![], vec![], vec![id]);
        let segment = DAGSegment::new(vec![node], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::SelfParent { node: id })
        );
    }

    #[test]
    fn duplicate_parents_are_rejected() {
        let root = root_node(1);
        let child = DAGNode::new(
            Hash::new([2u8; 32]),
            vec![0x02],
            vec![],
            vec![],
            vec![root.node_id, root.node_id],
        );
        let segment = DAGSegment::new(vec![root.clone(), child], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::DuplicateParent {
                node: Hash::new([2u8; 32]),
                parent: root.node_id,
            })
        );
    }

    #[test]
    fn missing_parents_are_rejected() {
        let absent = Hash::new([99u8; 32]);
        let node = child_node(1, vec![absent]);
        let segment = DAGSegment::new(vec![node.clone()], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::MissingParent {
                node: node.node_id,
                parent: absent,
            })
        );
    }

    #[test]
    fn cycles_are_rejected() {
        // a → b → a. Declared identifiers make the cycle expressible.
        let a = Hash::new([1u8; 32]);
        let b = Hash::new([2u8; 32]);
        let node_a = DAGNode::new(a, vec![0x01], vec![], vec![], vec![b]);
        let node_b = DAGNode::new(b, vec![0x02], vec![], vec![], vec![a]);
        let segment = DAGSegment::new(vec![node_a, node_b], Hash::zero());
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::Cycle { node: a })
        );
    }

    #[test]
    fn a_cycle_behind_a_valid_root_is_rejected() {
        let root = Hash::new([1u8; 32]);
        let a = Hash::new([2u8; 32]);
        let b = Hash::new([3u8; 32]);
        let segment = DAGSegment::new(
            vec![
                DAGNode::new(root, vec![0x00], vec![], vec![], vec![]),
                DAGNode::new(a, vec![0x01], vec![], vec![], vec![root, b]),
                DAGNode::new(b, vec![0x02], vec![], vec![], vec![a]),
            ],
            Hash::zero(),
        );
        assert_eq!(
            segment.validate_structure(),
            Err(DagStructureError::Cycle { node: a })
        );
    }

    #[test]
    fn non_canonical_order_is_rejected() {
        let segment = simple_chain();
        let mut reordered = segment.clone();
        reordered.nodes.reverse();
        let failure = reordered.validate_structure().expect_err("must reject");
        assert!(
            matches!(failure, DagStructureError::NonCanonicalOrder { .. }),
            "unexpected failure: {failure}"
        );
    }

    #[test]
    fn a_reordered_graph_is_never_accepted_under_a_second_identity() {
        // The acceptance property: reordering either canonicalizes to the same
        // identity or is rejected — never accepted with a different one.
        let root = root_node(1);
        let a = child_node(2, vec![root.node_id]);
        let b = child_node(3, vec![root.node_id]);

        let forward = DAGSegment::sealed(vec![root.clone(), a.clone(), b.clone()]).unwrap();
        let shuffled = DAGSegment::sealed(vec![b, root, a]).unwrap();

        assert_eq!(forward.root_commitment, shuffled.root_commitment);
        assert_eq!(
            forward.nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
            shuffled.nodes.iter().map(|n| n.node_id).collect::<Vec<_>>()
        );

        // And the non-canonical listing of the same nodes is refused outright.
        let mut hostile = forward.clone();
        hostile.nodes.swap(1, 2);
        assert!(matches!(
            hostile.validate_structure(),
            Err(DagStructureError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn each_hostile_property_reports_its_own_error() {
        let root = root_node(1);
        let child = child_node(2, vec![root.node_id]);
        let canonical = DAGSegment::sealed(vec![root.clone(), child.clone()]).unwrap();

        let empty = DAGSegment::new(vec![], Hash::zero());
        let duplicate = DAGSegment::new(vec![root.clone(), root.clone()], Hash::zero());
        let self_parent = DAGSegment::new(
            vec![DAGNode::new(
                Hash::new([5u8; 32]),
                vec![],
                vec![],
                vec![],
                vec![Hash::new([5u8; 32])],
            )],
            Hash::zero(),
        );
        let cyclic = DAGSegment::new(
            vec![
                DAGNode::new(
                    Hash::new([6u8; 32]),
                    vec![],
                    vec![],
                    vec![],
                    vec![Hash::new([7u8; 32])],
                ),
                DAGNode::new(
                    Hash::new([7u8; 32]),
                    vec![],
                    vec![],
                    vec![],
                    vec![Hash::new([6u8; 32])],
                ),
            ],
            Hash::zero(),
        );
        let mut noncanonical = canonical.clone();
        noncanonical.nodes.reverse();

        let reasons = [
            empty.validate_structure().unwrap_err(),
            duplicate.validate_structure().unwrap_err(),
            self_parent.validate_structure().unwrap_err(),
            cyclic.validate_structure().unwrap_err(),
            noncanonical.validate_structure().unwrap_err(),
        ];

        // Distinct variants, and distinct rendered messages.
        let rendered: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
        assert_eq!(rendered.len(), reasons.len(), "{rendered:?}");
        assert!(matches!(reasons[0], DagStructureError::EmptySegment));
        assert!(matches!(
            reasons[1],
            DagStructureError::DuplicateNodeId { .. }
        ));
        assert!(matches!(reasons[2], DagStructureError::SelfParent { .. }));
        assert!(matches!(reasons[3], DagStructureError::Cycle { .. }));
        assert!(matches!(
            reasons[4],
            DagStructureError::NonCanonicalOrder { .. }
        ));
    }

    // ─────────────────────────────────────────────
    // Public order and root accessors (PAR-DAG-002)
    // ─────────────────────────────────────────────

    #[test]
    fn an_ambiguous_graph_has_no_canonical_order_or_root() {
        // `canonical_order`/`canonical_root` are the values a caller compares a
        // declared identity against. A graph with duplicate identifiers or an
        // unresolvable parent must not yield one, or the comparison would be
        // made against an order the segment does not well-pose.
        let node = root_node(1);
        let duplicate = DAGSegment::new(vec![node.clone(), node.clone()], Hash::zero());
        assert_eq!(
            duplicate.canonical_order(),
            Err(DagStructureError::DuplicateNodeId { node: node.node_id })
        );
        assert_eq!(
            duplicate.canonical_root(),
            Err(DagStructureError::DuplicateNodeId { node: node.node_id })
        );

        let absent = Hash::new([99u8; 32]);
        let orphan = DAGSegment::new(vec![child_node(1, vec![absent])], Hash::zero());
        assert!(matches!(
            orphan.canonical_root(),
            Err(DagStructureError::MissingParent { .. })
        ));

        let empty = DAGSegment::new(vec![], Hash::zero());
        assert_eq!(
            empty.canonical_order(),
            Err(DagStructureError::EmptySegment)
        );
        assert_eq!(empty.canonical_root(), Err(DagStructureError::EmptySegment));
    }

    #[test]
    fn a_canonical_graph_orders_and_roots_consistently() {
        let segment = simple_chain();
        assert_eq!(
            segment.canonical_order().unwrap(),
            segment.nodes.iter().map(|n| n.node_id).collect::<Vec<_>>()
        );
        assert_eq!(segment.canonical_root().unwrap(), segment.root_commitment);
    }

    // ─────────────────────────────────────────────
    // Roots and disconnected components (PAR-DAG-002)
    // ─────────────────────────────────────────────

    #[test]
    fn multiple_roots_and_disconnected_components_are_permitted() {
        // Two parallel histories in one segment, each with its own root.
        let root_a = root_node(1);
        let child_a = child_node(2, vec![root_a.node_id]);
        let root_b = root_node(3);
        let child_b = child_node(4, vec![root_b.node_id]);

        let segment = DAGSegment::sealed(vec![root_a, child_a, root_b, child_b])
            .expect("disconnected components are permitted");
        assert_eq!(segment.roots().len(), 2);
        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn a_diamond_has_one_root_and_validates() {
        let root = root_node(0);
        let left = child_node(1, vec![root.node_id]);
        let right = child_node(2, vec![root.node_id]);
        let leaf = child_node(3, vec![left.node_id, right.node_id]);

        let segment = DAGSegment::sealed(vec![root, left, right, leaf]).unwrap();
        assert_eq!(segment.roots().len(), 1);
        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn a_long_chain_validates() {
        let mut nodes = vec![root_node(0)];
        for tag in 1..64u8 {
            let parent = nodes.last().unwrap().node_id;
            nodes.push(child_node(tag, vec![parent]));
        }
        let segment = DAGSegment::sealed(nodes).unwrap();
        assert_eq!(segment.nodes.len(), 64);
        assert_eq!(segment.roots().len(), 1);
        assert!(segment.validate_structure().is_ok());
    }

    // ─────────────────────────────────────────────
    // Generated hostile graphs (PAR-DAG-002)
    //
    // Fixed fixtures only prove the cases someone thought of. These generate
    // graphs from a deterministic PRNG and assert the invariant that matters:
    // a hostile graph never validates, and a canonical one always does.
    // ─────────────────────────────────────────────

    /// SplitMix64 — deterministic, seedable, no dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next() % bound as u64) as usize
            }
        }

        fn byte(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    /// A random canonical segment: nodes only ever reference earlier nodes, so
    /// the result is acyclic by construction.
    fn generate_canonical(rng: &mut Rng, size: usize) -> DAGSegment {
        let mut nodes: Vec<DAGNode> = Vec::with_capacity(size);
        for _ in 0..size {
            let mut parents = Vec::new();
            if !nodes.is_empty() {
                let want = rng.below(3.min(nodes.len()) + 1);
                let mut chosen = BTreeSet::new();
                for _ in 0..want {
                    chosen.insert(nodes[rng.below(nodes.len())].node_id);
                }
                parents = chosen.into_iter().collect();
            }
            nodes.push(DAGNode::sealed(
                vec![rng.byte(), rng.byte()],
                vec![vec![rng.byte(); 4]],
                vec![],
                parents,
            ));
        }
        DAGSegment::sealed(nodes).expect("generated graph is acyclic by construction")
    }

    #[test]
    fn generated_canonical_graphs_always_validate() {
        for seed in 0..256u64 {
            let mut rng = Rng(seed);
            let size = 1 + rng.below(12);
            let segment = generate_canonical(&mut rng, size);
            assert!(
                segment.validate_structure().is_ok(),
                "seed {seed}: canonical graph rejected"
            );
        }
    }

    #[test]
    fn generated_canonical_graphs_have_a_stable_identity_under_reordering() {
        for seed in 0..128u64 {
            let mut rng = Rng(seed);
            let size = 2 + rng.below(10);
            let segment = generate_canonical(&mut rng, size);

            let mut shuffled = segment.nodes.clone();
            for index in (1..shuffled.len()).rev() {
                shuffled.swap(index, rng.below(index + 1));
            }
            let resealed = DAGSegment::sealed(shuffled).expect("same nodes, different order");
            assert_eq!(
                segment.root_commitment, resealed.root_commitment,
                "seed {seed}: reordering changed the segment identity"
            );
        }
    }

    /// A graph whose declared identifiers form a cycle of `length` nodes,
    /// optionally hanging further nodes off it.
    ///
    /// Built with the unchecked constructors: a cycle among content-derived
    /// identifiers would require a hash cycle, so this is the only way to
    /// express the shape the verifier has to reject.
    fn generate_cyclic(rng: &mut Rng, length: usize, tail: usize) -> DAGSegment {
        assert!(length >= 2, "a cycle needs at least two nodes");
        let ids: Vec<Hash> = (0..length + tail)
            .map(|position| {
                let mut bytes = [0u8; 32];
                bytes[0] = rng.byte();
                bytes[31] = position as u8;
                Hash::new(bytes)
            })
            .collect();

        let mut nodes: Vec<DAGNode> = Vec::with_capacity(ids.len());
        for position in 0..length {
            // Each cycle member parents the previous one, and the first parents
            // the last: no member can ever reach zero pending parents.
            let parent = ids[(position + length - 1) % length];
            nodes.push(DAGNode::new(
                ids[position],
                vec![rng.byte()],
                vec![],
                vec![],
                vec![parent],
            ));
        }
        // Nodes outside the cycle, some of them reachable roots, so the sort has
        // real work to do before it gets stuck.
        for position in length..ids.len() {
            let parents = if rng.below(2) == 0 {
                Vec::new()
            } else {
                vec![ids[rng.below(position)]]
            };
            nodes.push(DAGNode::new(
                ids[position],
                vec![rng.byte()],
                vec![],
                vec![],
                parents,
            ));
        }

        // Shuffle, so the sort cannot be rescued by a convenient listing order.
        for index in (1..nodes.len()).rev() {
            nodes.swap(index, rng.below(index + 1));
        }
        DAGSegment::new(nodes, Hash::zero())
    }

    #[test]
    fn generated_cyclic_graphs_are_always_rejected_as_cycles() {
        for seed in 0..256u64 {
            let mut rng = Rng(seed ^ 0xC0FF_EE00);
            let length = 2 + rng.below(6);
            let tail = rng.below(5);
            let segment = generate_cyclic(&mut rng, length, tail);

            let failure = segment
                .validate_structure()
                .expect_err("a cyclic graph must never validate");
            assert!(
                matches!(failure, DagStructureError::Cycle { .. }),
                "seed {seed}: cycle reported as {failure}"
            );
            // The reported node is one that is genuinely stuck, and the same one
            // every run: a conformance vector can pin it.
            assert_eq!(segment.canonical_order().unwrap_err(), failure);
        }
    }

    /// Every way we know to make a graph hostile.
    #[derive(Clone, Copy, Debug)]
    enum Corruption {
        MutateBytecode,
        MutateSignature,
        SubstituteRoot,
        DuplicateNode,
        SelfParent,
        DuplicateParent,
        DropParentNode,
        RepointParent,
        IntroduceCycle,
        Reorder,
        Truncate,
    }

    const CORRUPTIONS: [Corruption; 11] = [
        Corruption::MutateBytecode,
        Corruption::MutateSignature,
        Corruption::SubstituteRoot,
        Corruption::DuplicateNode,
        Corruption::SelfParent,
        Corruption::DuplicateParent,
        Corruption::DropParentNode,
        Corruption::RepointParent,
        Corruption::IntroduceCycle,
        Corruption::Reorder,
        Corruption::Truncate,
    ];

    /// Apply one corruption. Returns `None` when the generated graph has no
    /// shape the corruption applies to (e.g. reordering a single node).
    fn corrupt(segment: &DAGSegment, how: Corruption, rng: &mut Rng) -> Option<DAGSegment> {
        let mut hostile = segment.clone();
        let target = rng.below(hostile.nodes.len());
        match how {
            Corruption::MutateBytecode => {
                hostile.nodes[target].bytecode.push(rng.byte());
            }
            Corruption::MutateSignature => {
                hostile.nodes[target].signatures.push(vec![rng.byte(); 8]);
            }
            Corruption::SubstituteRoot => {
                let substituted = Hash::new([rng.byte(); 32]);
                if substituted == hostile.root_commitment {
                    return None;
                }
                hostile.root_commitment = substituted;
            }
            Corruption::DuplicateNode => {
                let clone = hostile.nodes[target].clone();
                hostile.nodes.push(clone);
            }
            Corruption::SelfParent => {
                let id = hostile.nodes[target].node_id;
                hostile.nodes[target].parents.push(id);
            }
            Corruption::DuplicateParent => {
                let parent = *hostile.nodes[target].parents.first()?;
                hostile.nodes[target].parents.push(parent);
            }
            Corruption::DropParentNode => {
                // Remove a node that someone still references.
                let referenced: BTreeSet<Hash> = hostile
                    .nodes
                    .iter()
                    .flat_map(|node| node.parents.iter().copied())
                    .collect();
                let victim = hostile
                    .nodes
                    .iter()
                    .position(|node| referenced.contains(&node.node_id))?;
                hostile.nodes.remove(victim);
            }
            Corruption::RepointParent => {
                let slot = rng.below(hostile.nodes[target].parents.len().max(1));
                if hostile.nodes[target].parents.is_empty() {
                    return None;
                }
                hostile.nodes[target].parents[slot] = Hash::new([rng.byte() ^ 0x5A; 32]);
            }
            Corruption::IntroduceCycle => {
                // Turn an existing edge into a two-node cycle: give a node's
                // parent that node as a parent in return. Every reference still
                // resolves, so only acyclicity can catch it.
                let child = hostile
                    .nodes
                    .iter()
                    .position(|node| !node.parents.is_empty())?;
                let child_id = hostile.nodes[child].node_id;
                let parent_id = hostile.nodes[child].parents[0];
                let parent = hostile
                    .nodes
                    .iter()
                    .position(|node| node.node_id == parent_id)?;
                hostile.nodes[parent].parents.push(child_id);
            }
            Corruption::Reorder => {
                if hostile.nodes.len() < 2 {
                    return None;
                }
                hostile.nodes.reverse();
                if hostile
                    .nodes
                    .iter()
                    .map(|node| node.node_id)
                    .eq(segment.nodes.iter().map(|node| node.node_id))
                {
                    return None;
                }
            }
            Corruption::Truncate => {
                if hostile.nodes.len() < 2 {
                    return None;
                }
                hostile.nodes.pop();
            }
        }
        Some(hostile)
    }

    #[test]
    fn generated_hostile_graphs_never_validate() {
        let mut checked = 0usize;
        let mut exercised: BTreeSet<String> = BTreeSet::new();
        for seed in 0..512u64 {
            let mut rng = Rng(seed ^ 0xDEAD_BEEF);
            let size = 2 + rng.below(10);
            let canonical = generate_canonical(&mut rng, size);

            for how in CORRUPTIONS {
                let Some(hostile) = corrupt(&canonical, how, &mut rng) else {
                    continue;
                };
                checked += 1;
                exercised.insert(format!("{how:?}"));
                let failure = hostile
                    .validate_structure()
                    .expect_err(&format!("seed {seed}: {how:?} still validates"));
                // Where the corruption determines the reason, pin it: a graph
                // that fails for the wrong reason is a rule that is not being
                // enforced, only compensated for by another.
                match how {
                    Corruption::SelfParent => assert!(
                        matches!(failure, DagStructureError::SelfParent { .. }),
                        "seed {seed}: self-parenting reported as {failure}"
                    ),
                    Corruption::DuplicateNode => assert!(
                        matches!(failure, DagStructureError::DuplicateNodeId { .. }),
                        "seed {seed}: duplicate node reported as {failure}"
                    ),
                    Corruption::DuplicateParent => assert!(
                        matches!(failure, DagStructureError::DuplicateParent { .. }),
                        "seed {seed}: duplicate parent reported as {failure}"
                    ),
                    Corruption::IntroduceCycle => assert!(
                        matches!(failure, DagStructureError::Cycle { .. }),
                        "seed {seed}: cycle reported as {failure}"
                    ),
                    Corruption::SubstituteRoot => assert!(
                        matches!(failure, DagStructureError::RootMismatch { .. }),
                        "seed {seed}: substituted root reported as {failure}"
                    ),
                    _ => {}
                }
            }
        }
        assert!(
            checked > 1000,
            "the corpus must actually exercise the corruptions"
        );
        assert_eq!(
            exercised.len(),
            CORRUPTIONS.len(),
            "every corruption must reach at least one generated graph: {exercised:?}"
        );
    }

    #[test]
    fn generated_hostile_graphs_never_reuse_a_canonical_identity() {
        // Beyond "it fails": a corrupted graph must not be able to present the
        // canonical root as its own.
        for seed in 0..256u64 {
            let mut rng = Rng(seed ^ 0x0BAD_F00D);
            let size = 2 + rng.below(8);
            let canonical = generate_canonical(&mut rng, size);

            for how in [
                Corruption::MutateBytecode,
                Corruption::MutateSignature,
                Corruption::RepointParent,
                Corruption::Truncate,
            ] {
                let Some(hostile) = corrupt(&canonical, how, &mut rng) else {
                    continue;
                };
                if let Ok(root) = hostile.canonical_root() {
                    assert_ne!(
                        root, canonical.root_commitment,
                        "seed {seed}: {how:?} kept the canonical root"
                    );
                }
            }
        }
    }

    // ─────────────────────────────────────────────
    // Serialization (unchanged: decoding must accept what validation rejects)
    // ─────────────────────────────────────────────

    #[test]
    fn node_serialization_roundtrip() {
        let node = DAGNode::sealed(
            vec![0x01, 0x02, 0x03],
            vec![vec![0xAB; 64]],
            vec![vec![0xCD; 32]],
            vec![Hash::new([4u8; 32])],
        );
        let bytes = node.to_canonical_bytes();
        let restored = DAGNode::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(node, restored);
        assert_eq!(node.node_id, restored.canonical_id());
    }

    #[test]
    fn segment_serialization_roundtrip_preserves_validity() {
        let segment = simple_chain();
        let bytes = segment.to_canonical_bytes();
        let restored = DAGSegment::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(segment, restored);
        assert!(restored.validate_structure().is_ok());
    }

    #[test]
    fn decoding_accepts_hostile_bytes_so_validation_can_reject_them() {
        // A decoder that refused hostile input would move the rejection out of
        // the verifier and into the parser, where it has no error vocabulary.
        let hostile = DAGSegment::new(
            vec![DAGNode::new(
                Hash::new([1u8; 32]),
                vec![0x01],
                vec![],
                vec![],
                vec![Hash::new([1u8; 32])],
            )],
            Hash::zero(),
        );
        let bytes = hostile.to_canonical_bytes();
        let restored = DAGSegment::from_canonical_bytes(&bytes).expect("decodes");
        assert_eq!(
            restored.validate_structure(),
            Err(DagStructureError::SelfParent {
                node: Hash::new([1u8; 32])
            })
        );
    }
}
