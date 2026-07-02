//! Merkleized content tree system
//!
//! Provides a canonical Merkle tree structure for organizing Sanad content.
//! Supports selective disclosure, encrypted subtrees, and resource accounting.
//!
//! # Design
//!
//! The content tree is a binary Merkle tree where:
//! - Leaf nodes contain content chunks or metadata
//! - Internal nodes contain hashes of their children
//! - The root hash commits to all content
//! - Proofs can verify individual leaves without revealing the full tree

use std::vec::Vec;

use csv_hash::{Hash, merkle::tree::MerkleTree as CanonicalMerkleTree};
use serde::{Deserialize, Serialize};
// L2 types containing L0 Hash fields cannot use serde
// Use manual serialization instead

/// The type of a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// A leaf node containing content data.
    Leaf,
    /// An internal node containing hashes of children.
    Internal,
    /// An encrypted subtree node.
    Encrypted,
    /// A metadata node (schema, encoding, etc.).
    Metadata,
}

/// A node in the content tree.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct ContentNode {
    /// The type of this node.
    pub node_type: NodeType,
    /// The hash of this node (computed from children or data).
    pub hash: Hash,
    /// For leaf nodes: the content data.
    pub data: Option<Vec<u8>>,
    /// For internal nodes: the hashes of child nodes.
    pub children: Vec<Hash>,
    /// Optional encryption key ID for encrypted nodes.
    pub encryption_key_id: Option<String>,
    /// Node metadata (schema version, encoding, etc.).
    pub metadata: NodeMetadata,
}

impl serde::Serialize for ContentNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ContentNode", 6)?;
        s.serialize_field("node_type", &self.node_type)?;
        s.serialize_field("hash", &self.hash.0)?;
        s.serialize_field("data", &self.data)?;
        s.serialize_field(
            "children",
            &self.children.iter().map(|h| h.0).collect::<Vec<_>>(),
        )?;
        s.serialize_field("encryption_key_id", &self.encryption_key_id)?;
        s.serialize_field("metadata", &self.metadata)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for ContentNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            NodeType,
            Hash,
            Data,
            Children,
            EncryptionKeyId,
            Metadata,
        }

        struct ContentNodeVisitor;

        impl<'de> serde::de::Visitor<'de> for ContentNodeVisitor {
            type Value = ContentNode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ContentNode")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let node_type = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let data = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let children_bytes: Vec<[u8; 32]> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let encryption_key_id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                let metadata = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                Ok(ContentNode {
                    node_type,
                    hash: Hash(hash_bytes),
                    data,
                    children: children_bytes.into_iter().map(Hash).collect(),
                    encryption_key_id,
                    metadata,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut node_type = None;
                let mut hash = None;
                let mut data = None;
                let mut children = None;
                let mut encryption_key_id = None;
                let mut metadata = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::NodeType => {
                            if node_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("node_type"));
                            }
                            node_type = Some(map.next_value()?);
                        }
                        Field::Hash => {
                            if hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            hash = Some(Hash(hash_bytes));
                        }
                        Field::Data => {
                            if data.is_some() {
                                return Err(serde::de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        }
                        Field::Children => {
                            if children.is_some() {
                                return Err(serde::de::Error::duplicate_field("children"));
                            }
                            let children_bytes: Vec<[u8; 32]> = map.next_value()?;
                            children = Some(children_bytes.into_iter().map(Hash).collect());
                        }
                        Field::EncryptionKeyId => {
                            if encryption_key_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("encryption_key_id"));
                            }
                            encryption_key_id = Some(map.next_value()?);
                        }
                        Field::Metadata => {
                            if metadata.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata = Some(map.next_value()?);
                        }
                    }
                }

                let node_type =
                    node_type.ok_or_else(|| serde::de::Error::missing_field("node_type"))?;
                let hash = hash.ok_or_else(|| serde::de::Error::missing_field("hash"))?;
                let data = data.ok_or_else(|| serde::de::Error::missing_field("data"))?;
                let children =
                    children.ok_or_else(|| serde::de::Error::missing_field("children"))?;
                let metadata =
                    metadata.ok_or_else(|| serde::de::Error::missing_field("metadata"))?;

                Ok(ContentNode {
                    node_type,
                    hash,
                    data,
                    children,
                    encryption_key_id,
                    metadata,
                })
            }
        }

        deserializer.deserialize_struct(
            "ContentNode",
            &[
                "node_type",
                "hash",
                "data",
                "children",
                "encryption_key_id",
                "metadata",
            ],
            ContentNodeVisitor,
        )
    }
}

/// Metadata for a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMetadata {
    /// Schema ID for this node.
    pub schema_id: Option<String>,
    /// Encoding type (e.g., "json", "protobuf", "cbor").
    pub encoding: Option<String>,
    /// Content type (e.g., "text/plain", "application/pdf").
    pub content_type: Option<String>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Access control list for this node.
    pub access_control: Option<AccessControl>,
}

/// Access control for a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessControl {
    /// Who can read this node.
    pub readers: Vec<String>,
    /// Who can write this node.
    pub writers: Vec<String>,
    /// Minimum disclosure level required.
    pub min_disclosure_level: u8,
}

/// A content tree with Merkle-based integrity.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct ContentTree {
    /// The root hash of the tree.
    pub root_hash: Hash,
    /// All leaf hashes in order.
    pub leaf_hashes: Vec<Hash>,
    /// Tree depth.
    pub depth: usize,
    /// Number of leaves.
    pub leaf_count: usize,
    /// Node metadata indexed by hash.
    pub node_metadata: std::collections::HashMap<Hash, NodeMetadata>,
}

impl serde::Serialize for ContentTree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ContentTree", 5)?;
        s.serialize_field("root_hash", &self.root_hash.0)?;
        s.serialize_field(
            "leaf_hashes",
            &self.leaf_hashes.iter().map(|h| h.0).collect::<Vec<_>>(),
        )?;
        s.serialize_field("depth", &self.depth)?;
        s.serialize_field("leaf_count", &self.leaf_count)?;
        // Serialize HashMap as Vec of (hash_bytes, metadata) tuples
        let metadata_vec: Vec<([u8; 32], NodeMetadata)> = self
            .node_metadata
            .iter()
            .map(|(k, v)| (k.0, v.clone()))
            .collect();
        s.serialize_field("node_metadata", &metadata_vec)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for ContentTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            RootHash,
            LeafHashes,
            Depth,
            LeafCount,
            NodeMetadata,
        }

        struct ContentTreeVisitor;

        impl<'de> serde::de::Visitor<'de> for ContentTreeVisitor {
            type Value = ContentTree;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ContentTree")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let root_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let leaf_hashes_bytes: Vec<[u8; 32]> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let depth = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let leaf_count = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let metadata_vec: Vec<([u8; 32], NodeMetadata)> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                let node_metadata: std::collections::HashMap<Hash, NodeMetadata> = metadata_vec
                    .into_iter()
                    .map(|(k, v)| (Hash(k), v))
                    .collect();
                Ok(ContentTree {
                    root_hash: Hash(root_hash_bytes),
                    leaf_hashes: leaf_hashes_bytes.into_iter().map(Hash).collect(),
                    depth,
                    leaf_count,
                    node_metadata,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut root_hash = None;
                let mut leaf_hashes = None;
                let mut depth = None;
                let mut leaf_count = None;
                let mut node_metadata = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RootHash => {
                            if root_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("root_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            root_hash = Some(Hash(hash_bytes));
                        }
                        Field::LeafHashes => {
                            if leaf_hashes.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaf_hashes"));
                            }
                            let hashes_bytes: Vec<[u8; 32]> = map.next_value()?;
                            leaf_hashes = Some(hashes_bytes.into_iter().map(Hash).collect());
                        }
                        Field::Depth => {
                            if depth.is_some() {
                                return Err(serde::de::Error::duplicate_field("depth"));
                            }
                            depth = Some(map.next_value()?);
                        }
                        Field::LeafCount => {
                            if leaf_count.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaf_count"));
                            }
                            leaf_count = Some(map.next_value()?);
                        }
                        Field::NodeMetadata => {
                            if node_metadata.is_some() {
                                return Err(serde::de::Error::duplicate_field("node_metadata"));
                            }
                            // Deserialize Vec of tuples and convert to HashMap
                            let metadata_vec: Vec<([u8; 32], NodeMetadata)> = map.next_value()?;
                            node_metadata = Some(
                                metadata_vec
                                    .into_iter()
                                    .map(|(k, v)| (Hash(k), v))
                                    .collect(),
                            );
                        }
                    }
                }

                let root_hash =
                    root_hash.ok_or_else(|| serde::de::Error::missing_field("root_hash"))?;
                let leaf_hashes =
                    leaf_hashes.ok_or_else(|| serde::de::Error::missing_field("leaf_hashes"))?;
                let depth = depth.ok_or_else(|| serde::de::Error::missing_field("depth"))?;
                let leaf_count =
                    leaf_count.ok_or_else(|| serde::de::Error::missing_field("leaf_count"))?;
                let node_metadata = node_metadata
                    .ok_or_else(|| serde::de::Error::missing_field("node_metadata"))?;

                Ok(ContentTree {
                    root_hash,
                    leaf_hashes,
                    depth,
                    leaf_count,
                    node_metadata,
                })
            }
        }

        deserializer.deserialize_struct(
            "ContentTree",
            &[
                "root_hash",
                "leaf_hashes",
                "depth",
                "leaf_count",
                "node_metadata",
            ],
            ContentTreeVisitor,
        )
    }
}

impl ContentTree {
    /// Create a new content tree from leaf data.
    ///
    /// # Arguments
    /// * `leaves` - Slice of leaf data to include in the tree
    ///
    /// # Returns
    /// The constructed ContentTree
    pub fn from_leaves(leaves: Vec<Vec<u8>>) -> Self {
        if leaves.is_empty() {
            return Self::empty();
        }

        // Hash each leaf with domain separation
        let leaf_hashes: Vec<Hash> = leaves.iter().map(|data| Self::hash_leaf(data)).collect();

        // Build canonical Merkle tree
        let canonical = match CanonicalMerkleTree::from_leaves(leaf_hashes.clone()) {
            Some(canonical) => canonical,
            None => return Self::empty(),
        };

        Self {
            root_hash: canonical.root,
            leaf_hashes,
            depth: canonical.depth,
            leaf_count: canonical.leaf_count(),
            node_metadata: std::collections::HashMap::new(),
        }
    }

    /// Create an empty content tree.
    pub fn empty() -> Self {
        Self {
            root_hash: Hash::default(),
            leaf_hashes: Vec::new(),
            depth: 0,
            leaf_count: 0,
            node_metadata: std::collections::HashMap::new(),
        }
    }

    /// Hash a leaf value with domain separation.
    pub fn hash_leaf(data: &[u8]) -> Hash {
        CanonicalMerkleTree::hash_leaf(data)
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf (0-based)
    ///
    /// # Returns
    /// A ContentProof if the index is valid
    pub fn proof(&self, leaf_index: usize) -> Option<ContentProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        // Build a temporary canonical tree to generate the proof
        let canonical = CanonicalMerkleTree::from_leaves(self.leaf_hashes.clone())?;
        let merkle_proof = canonical.proof(leaf_index)?;

        Some(ContentProof {
            leaf_index,
            leaf_hash: self.leaf_hashes[leaf_index],
            siblings: merkle_proof.siblings,
            root_hash: self.root_hash,
        })
    }

    /// Verify a leaf is included in this tree.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf
    /// * `leaf_data` - Raw leaf data
    ///
    /// # Returns
    /// True if the leaf is included
    pub fn verify_inclusion(&self, leaf_index: usize, leaf_data: &[u8]) -> bool {
        let leaf_hash = Self::hash_leaf(leaf_data);
        if let Some(proof) = self.proof(leaf_index) {
            proof.verify(leaf_hash)
        } else {
            false
        }
    }

    /// Add metadata for a node.
    pub fn set_node_metadata(&mut self, hash: Hash, metadata: NodeMetadata) {
        self.node_metadata.insert(hash, metadata);
    }

    /// Get metadata for a node.
    pub fn get_node_metadata(&self, hash: &Hash) -> Option<&NodeMetadata> {
        self.node_metadata.get(hash)
    }

    /// Compute the verification cost for this tree.
    pub fn verification_cost(&self) -> VerificationCost {
        VerificationCost {
            cpu: self.leaf_count as u64 * 10,
            memory: (self.leaf_count as u64) * 32 * (self.depth as u64 + 1),
            io: self.leaf_count as u64,
            recursion_depth: self.depth as u32,
        }
    }
}

impl Default for ContentTree {
    fn default() -> Self {
        Self::empty()
    }
}

/// A proof that a leaf is included in a content tree.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct ContentProof {
    /// Index of the leaf in the tree.
    pub leaf_index: usize,
    /// Hash of the leaf.
    pub leaf_hash: Hash,
    /// Sibling hashes along the proof path.
    pub siblings: Vec<Hash>,
    /// Expected root hash.
    pub root_hash: Hash,
}

impl serde::Serialize for ContentProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ContentProof", 4)?;
        s.serialize_field("leaf_index", &self.leaf_index)?;
        s.serialize_field("leaf_hash", &self.leaf_hash.0)?;
        s.serialize_field(
            "siblings",
            &self.siblings.iter().map(|h| h.0).collect::<Vec<_>>(),
        )?;
        s.serialize_field("root_hash", &self.root_hash.0)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for ContentProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            LeafIndex,
            LeafHash,
            Siblings,
            RootHash,
        }

        struct ContentProofVisitor;

        impl<'de> serde::de::Visitor<'de> for ContentProofVisitor {
            type Value = ContentProof;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ContentProof")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let leaf_index = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let leaf_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let siblings_bytes: Vec<[u8; 32]> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let root_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                Ok(ContentProof {
                    leaf_index,
                    leaf_hash: Hash(leaf_hash_bytes),
                    siblings: siblings_bytes.into_iter().map(Hash).collect(),
                    root_hash: Hash(root_hash_bytes),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut leaf_index = None;
                let mut leaf_hash = None;
                let mut siblings = None;
                let mut root_hash = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::LeafIndex => {
                            if leaf_index.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaf_index"));
                            }
                            leaf_index = Some(map.next_value()?);
                        }
                        Field::LeafHash => {
                            if leaf_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaf_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            leaf_hash = Some(Hash(hash_bytes));
                        }
                        Field::Siblings => {
                            if siblings.is_some() {
                                return Err(serde::de::Error::duplicate_field("siblings"));
                            }
                            let sibs_bytes: Vec<[u8; 32]> = map.next_value()?;
                            siblings = Some(sibs_bytes.into_iter().map(Hash).collect());
                        }
                        Field::RootHash => {
                            if root_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("root_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            root_hash = Some(Hash(hash_bytes));
                        }
                    }
                }

                let leaf_index =
                    leaf_index.ok_or_else(|| serde::de::Error::missing_field("leaf_index"))?;
                let leaf_hash =
                    leaf_hash.ok_or_else(|| serde::de::Error::missing_field("leaf_hash"))?;
                let siblings =
                    siblings.ok_or_else(|| serde::de::Error::missing_field("siblings"))?;
                let root_hash =
                    root_hash.ok_or_else(|| serde::de::Error::missing_field("root_hash"))?;

                Ok(ContentProof {
                    leaf_index,
                    leaf_hash,
                    siblings,
                    root_hash,
                })
            }
        }

        deserializer.deserialize_struct(
            "ContentProof",
            &["leaf_index", "leaf_hash", "siblings", "root_hash"],
            ContentProofVisitor,
        )
    }
}

impl ContentProof {
    /// Verify this proof against a leaf hash.
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf to verify
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, leaf_hash: Hash) -> bool {
        if leaf_hash != self.leaf_hash {
            return false;
        }

        // Use the canonical Merkle proof verification
        csv_hash::merkle::verifier::verify_merkle_proof(
            leaf_hash,
            &self.siblings,
            self.leaf_index,
            self.root_hash,
        )
    }

    /// Compute the root from this proof.
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf
    ///
    /// # Returns
    /// The computed root hash
    pub fn compute_root(&self, leaf_hash: Hash) -> Hash {
        csv_hash::merkle::verifier::compute_root_from_proof(
            leaf_hash,
            &self.siblings,
            self.leaf_index,
        )
    }
}

/// Resource accounting for verification paths.
///
/// Every verification path must calculate these costs
/// to reject pathological content.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationCost {
    /// Estimated CPU cycles.
    pub cpu: u64,
    /// Estimated memory bytes.
    pub memory: u64,
    /// Estimated I/O operations.
    pub io: u64,
    /// Maximum recursion depth.
    pub recursion_depth: u32,
}

impl VerificationCost {
    /// Check if this cost is within acceptable limits.
    ///
    /// # Arguments
    /// * `max_cpu` - Maximum allowed CPU cycles
    /// * `max_memory` - Maximum allowed memory bytes
    /// * `max_io` - Maximum allowed I/O operations
    /// * `max_recursion` - Maximum allowed recursion depth
    ///
    /// # Returns
    /// True if all limits are respected
    pub fn is_acceptable(
        &self,
        max_cpu: u64,
        max_memory: u64,
        max_io: u64,
        max_recursion: u32,
    ) -> bool {
        self.cpu <= max_cpu
            && self.memory <= max_memory
            && self.io <= max_io
            && self.recursion_depth <= max_recursion
    }

    /// Check if this cost exceeds any limit.
    ///
    /// # Returns
    /// An error message if any limit is exceeded, None otherwise
    pub fn validate(
        &self,
        max_cpu: u64,
        max_memory: u64,
        max_io: u64,
        max_recursion: u32,
    ) -> Result<(), VerificationCostError> {
        if self.cpu > max_cpu {
            return Err(VerificationCostError::CpuExceeded {
                requested: self.cpu,
                limit: max_cpu,
            });
        }
        if self.memory > max_memory {
            return Err(VerificationCostError::MemoryExceeded {
                requested: self.memory,
                limit: max_memory,
            });
        }
        if self.io > max_io {
            return Err(VerificationCostError::IoExceeded {
                requested: self.io,
                limit: max_io,
            });
        }
        if self.recursion_depth > max_recursion {
            return Err(VerificationCostError::RecursionDepthExceeded {
                requested: self.recursion_depth,
                limit: max_recursion,
            });
        }
        Ok(())
    }
}

/// Error when verification cost exceeds limits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationCostError {
    #[error("CPU cost exceeded: requested {requested}, limit {limit}")]
    CpuExceeded { requested: u64, limit: u64 },
    #[error("Memory cost exceeded: requested {requested}, limit {limit}")]
    MemoryExceeded { requested: u64, limit: u64 },
    #[error("I/O cost exceeded: requested {requested}, limit {limit}")]
    IoExceeded { requested: u64, limit: u64 },
    #[error("Recursion depth exceeded: requested {requested}, limit {limit}")]
    RecursionDepthExceeded { requested: u32, limit: u32 },
}

/// A selective disclosure proof.
///
/// Allows proving subtree validity without exposing the full content.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct DisclosureProof {
    /// The root of the disclosed subtree.
    pub subtree_root: Hash,
    /// Proof that the subtree root is included in the content tree root.
    pub inclusion_proof: ContentProof,
}

impl serde::Serialize for DisclosureProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("DisclosureProof", 2)?;
        s.serialize_field("subtree_root", &self.subtree_root.0)?;
        s.serialize_field("inclusion_proof", &self.inclusion_proof)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for DisclosureProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            SubtreeRoot,
            InclusionProof,
        }

        struct DisclosureProofVisitor;

        impl<'de> serde::de::Visitor<'de> for DisclosureProofVisitor {
            type Value = DisclosureProof;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct DisclosureProof")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let subtree_root_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let inclusion_proof = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(DisclosureProof {
                    subtree_root: Hash(subtree_root_bytes),
                    inclusion_proof,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut subtree_root = None;
                let mut inclusion_proof = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::SubtreeRoot => {
                            if subtree_root.is_some() {
                                return Err(serde::de::Error::duplicate_field("subtree_root"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            subtree_root = Some(Hash(hash_bytes));
                        }
                        Field::InclusionProof => {
                            if inclusion_proof.is_some() {
                                return Err(serde::de::Error::duplicate_field("inclusion_proof"));
                            }
                            inclusion_proof = Some(map.next_value()?);
                        }
                    }
                }

                let subtree_root =
                    subtree_root.ok_or_else(|| serde::de::Error::missing_field("subtree_root"))?;
                let inclusion_proof = inclusion_proof
                    .ok_or_else(|| serde::de::Error::missing_field("inclusion_proof"))?;

                Ok(DisclosureProof {
                    subtree_root,
                    inclusion_proof,
                })
            }
        }

        deserializer.deserialize_struct(
            "DisclosureProof",
            &["subtree_root", "inclusion_proof"],
            DisclosureProofVisitor,
        )
    }
}

impl DisclosureProof {
    /// Verify this disclosure proof.
    ///
    /// # Arguments
    /// * `content_root` - The root hash of the full content tree
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, content_root: Hash) -> bool {
        if self.inclusion_proof.root_hash != content_root {
            return false;
        }
        // Verify the subtree root is included in the content tree
        if !self.inclusion_proof.verify(self.subtree_root) {
            return false;
        }

        true
    }
}

/// A redacted Merkle proof.
///
/// Proves a leaf exists without revealing its content.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct RedactedMerkleProof {
    /// The hash of the redacted leaf.
    pub leaf_hash: Hash,
    /// The Merkle proof.
    pub proof: ContentProof,
    /// The redaction method used (e.g., "sha256", "blake3").
    pub redaction_method: String,
}

impl serde::Serialize for RedactedMerkleProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("RedactedMerkleProof", 3)?;
        s.serialize_field("leaf_hash", &self.leaf_hash.0)?;
        s.serialize_field("proof", &self.proof)?;
        s.serialize_field("redaction_method", &self.redaction_method)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for RedactedMerkleProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            LeafHash,
            Proof,
            RedactionMethod,
        }

        struct RedactedMerkleProofVisitor;

        impl<'de> serde::de::Visitor<'de> for RedactedMerkleProofVisitor {
            type Value = RedactedMerkleProof;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct RedactedMerkleProof")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let leaf_hash_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let proof = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let redaction_method = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                Ok(RedactedMerkleProof {
                    leaf_hash: Hash(leaf_hash_bytes),
                    proof,
                    redaction_method,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut leaf_hash = None;
                let mut proof = None;
                let mut redaction_method = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::LeafHash => {
                            if leaf_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("leaf_hash"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            leaf_hash = Some(Hash(hash_bytes));
                        }
                        Field::Proof => {
                            if proof.is_some() {
                                return Err(serde::de::Error::duplicate_field("proof"));
                            }
                            proof = Some(map.next_value()?);
                        }
                        Field::RedactionMethod => {
                            if redaction_method.is_some() {
                                return Err(serde::de::Error::duplicate_field("redaction_method"));
                            }
                            redaction_method = Some(map.next_value()?);
                        }
                    }
                }

                let leaf_hash =
                    leaf_hash.ok_or_else(|| serde::de::Error::missing_field("leaf_hash"))?;
                let proof = proof.ok_or_else(|| serde::de::Error::missing_field("proof"))?;
                let redaction_method = redaction_method
                    .ok_or_else(|| serde::de::Error::missing_field("redaction_method"))?;

                Ok(RedactedMerkleProof {
                    leaf_hash,
                    proof,
                    redaction_method,
                })
            }
        }

        deserializer.deserialize_struct(
            "RedactedMerkleProof",
            &["leaf_hash", "proof", "redaction_method"],
            RedactedMerkleProofVisitor,
        )
    }
}

impl RedactedMerkleProof {
    /// Verify this redacted proof.
    pub fn verify(&self) -> bool {
        self.proof.verify(self.leaf_hash)
    }
}

/// An encrypted subtree proof.
///
/// Proves knowledge of an encrypted subtree without revealing its contents.
/// L2 type: uses manual serialization for Hash fields
#[derive(Debug, Clone)]
pub struct EncryptedSubtreeProof {
    /// The hash of the encrypted subtree root.
    pub encrypted_root: Hash,
    /// Proof that the encrypted root is in the content tree.
    pub inclusion_proof: ContentProof,
    /// Encryption algorithm used.
    pub encryption_algorithm: String,
    /// Key ID used for encryption.
    pub key_id: String,
}

impl serde::Serialize for EncryptedSubtreeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("EncryptedSubtreeProof", 4)?;
        s.serialize_field("encrypted_root", &self.encrypted_root.0)?;
        s.serialize_field("inclusion_proof", &self.inclusion_proof)?;
        s.serialize_field("encryption_algorithm", &self.encryption_algorithm)?;
        s.serialize_field("key_id", &self.key_id)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for EncryptedSubtreeProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            EncryptedRoot,
            InclusionProof,
            EncryptionAlgorithm,
            KeyId,
        }

        struct EncryptedSubtreeProofVisitor;

        impl<'de> serde::de::Visitor<'de> for EncryptedSubtreeProofVisitor {
            type Value = EncryptedSubtreeProof;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct EncryptedSubtreeProof")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let encrypted_root_bytes: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let inclusion_proof = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let encryption_algorithm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let key_id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                Ok(EncryptedSubtreeProof {
                    encrypted_root: Hash(encrypted_root_bytes),
                    inclusion_proof,
                    encryption_algorithm,
                    key_id,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut encrypted_root = None;
                let mut inclusion_proof = None;
                let mut encryption_algorithm = None;
                let mut key_id = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::EncryptedRoot => {
                            if encrypted_root.is_some() {
                                return Err(serde::de::Error::duplicate_field("encrypted_root"));
                            }
                            let hash_bytes: [u8; 32] = map.next_value()?;
                            encrypted_root = Some(Hash(hash_bytes));
                        }
                        Field::InclusionProof => {
                            if inclusion_proof.is_some() {
                                return Err(serde::de::Error::duplicate_field("inclusion_proof"));
                            }
                            inclusion_proof = Some(map.next_value()?);
                        }
                        Field::EncryptionAlgorithm => {
                            if encryption_algorithm.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "encryption_algorithm",
                                ));
                            }
                            encryption_algorithm = Some(map.next_value()?);
                        }
                        Field::KeyId => {
                            if key_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("key_id"));
                            }
                            key_id = Some(map.next_value()?);
                        }
                    }
                }

                let encrypted_root = encrypted_root
                    .ok_or_else(|| serde::de::Error::missing_field("encrypted_root"))?;
                let inclusion_proof = inclusion_proof
                    .ok_or_else(|| serde::de::Error::missing_field("inclusion_proof"))?;
                let encryption_algorithm = encryption_algorithm
                    .ok_or_else(|| serde::de::Error::missing_field("encryption_algorithm"))?;
                let key_id = key_id.ok_or_else(|| serde::de::Error::missing_field("key_id"))?;

                Ok(EncryptedSubtreeProof {
                    encrypted_root,
                    inclusion_proof,
                    encryption_algorithm,
                    key_id,
                })
            }
        }

        deserializer.deserialize_struct(
            "EncryptedSubtreeProof",
            &[
                "encrypted_root",
                "inclusion_proof",
                "encryption_algorithm",
                "key_id",
            ],
            EncryptedSubtreeProofVisitor,
        )
    }
}

impl EncryptedSubtreeProof {
    /// Verify this encrypted subtree proof.
    pub fn verify(&self, content_root: Hash) -> bool {
        self.inclusion_proof.root_hash == content_root
            && self.inclusion_proof.verify(self.encrypted_root)
    }
}
