//! Proof DAGs (Directed Acyclic Graphs)
//!
//! Provides composable proof DAG structures for complex verification chains.
//! Proofs can depend on other proofs, forming a DAG that enables:
//! - Multi-step verification
//! - Proof aggregation
//! - Conditional proof composition
//! - Proof caching and reuse

use csv_hash::Hash;

use crate::Proof;

// L0/L1 types (proof data) use canonical_cbor for serialization
// L2 types (metadata) MAY use serde for configuration/indexing

/// A unique identifier for a proof node.
/// L0 type: hash wrapper - uses canonical_cbor for serialization
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofId(pub Hash);

impl ProofId {
    /// Create a new proof ID from a hash.
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Create a proof ID from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Hash::sha256(bytes))
    }

    /// Get the underlying hash.
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}

/// A node in a proof DAG.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Debug, Clone)]
pub struct ProofNode {
    /// Unique identifier for this node.
    pub id: ProofId,
    /// The proof contained in this node.
    pub proof: Proof,
    /// IDs of parent proofs this node depends on.
    pub dependencies: Vec<ProofId>,
    /// Metadata about this proof node.
    pub metadata: ProofNodeMetadata,
}

/// Metadata for a proof node.
#[derive(Debug, Clone, Default)]
pub struct ProofNodeMetadata {
    /// When the proof was created.
    pub created_at: u64,
    /// When the proof expires (0 = never).
    pub expires_at: u64,
    /// The chain or source of this proof.
    pub source: String,
    /// Additional arbitrary metadata.
    pub extra: std::collections::HashMap<String, String>,
}

impl ProofNode {
    /// Create a new proof node.
    pub fn new(proof: Proof, dependencies: Vec<ProofId>) -> Self {
        Self {
            id: ProofId::from_bytes(&proof.hash().0),
            proof,
            dependencies,
            metadata: ProofNodeMetadata::default(),
        }
    }

    /// Create a root node (no dependencies).
    pub fn root(proof: Proof) -> Self {
        Self::new(proof, Vec::new())
    }

    /// Set the creation timestamp.
    pub fn with_created_at(mut self, timestamp: u64) -> Self {
        self.metadata.created_at = timestamp;
        self
    }

    /// Set the expiration timestamp.
    pub fn with_expires_at(mut self, timestamp: u64) -> Self {
        self.metadata.expires_at = timestamp;
        self
    }

    /// Set the source.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.metadata.source = source.into();
        self
    }

    /// Check if this node is expired.
    pub fn is_expired(&self) -> bool {
        self.metadata.expires_at > 0 && self.metadata.expires_at < self.metadata.created_at
    }
}

/// A directed acyclic graph of proof nodes.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Debug, Clone, Default)]
pub struct ProofDag {
    /// All nodes in the DAG.
    pub nodes: std::collections::HashMap<ProofId, ProofNode>,
}

impl ProofDag {
    /// Create a new empty proof DAG.
    pub fn new() -> Self {
        Self {
            nodes: std::collections::HashMap::new(),
        }
    }

    /// Add a node to the DAG.
    ///
    /// # Arguments
    /// * `node` - The proof node to add
    ///
    /// # Returns
    /// True if the node was added successfully
    pub fn add_node(&mut self, node: ProofNode) -> bool {
        // Check that all dependencies exist
        for dep_id in &node.dependencies {
            if !self.nodes.contains_key(dep_id) {
                return false;
            }
        }

        // Add the node
        self.nodes.insert(node.id.clone(), node);
        true
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: &ProofId) -> Option<&ProofNode> {
        self.nodes.get(id)
    }

    /// Get all root nodes (nodes with no dependencies).
    pub fn roots(&self) -> Vec<&ProofNode> {
        self.nodes
            .values()
            .filter(|n| n.dependencies.is_empty())
            .collect()
    }

    /// Get all leaf nodes (nodes that no other node depends on).
    pub fn leaves(&self) -> Vec<&ProofNode> {
        let dependent_ids: std::collections::HashSet<&ProofId> = self
            .nodes
            .values()
            .flat_map(|n| n.dependencies.iter())
            .collect();

        self.nodes
            .values()
            .filter(|n| !dependent_ids.contains(&n.id))
            .collect()
    }

    /// Verify the DAG is acyclic using DFS.
    pub fn verify_acyclic(&self) -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut rec_stack = std::collections::HashSet::new();

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                if Self::has_cycle(node_id, &self.nodes, &mut visited, &mut rec_stack) {
                    return false;
                }
            }
        }
        true
    }

    /// DFS cycle detection helper.
    fn has_cycle(
        node_id: &ProofId,
        nodes: &std::collections::HashMap<ProofId, ProofNode>,
        visited: &mut std::collections::HashSet<ProofId>,
        rec_stack: &mut std::collections::HashSet<ProofId>,
    ) -> bool {
        visited.insert(node_id.clone());
        rec_stack.insert(node_id.clone());

        if let Some(node) = nodes.get(node_id) {
            for dep_id in &node.dependencies {
                if !visited.contains(dep_id) {
                    if Self::has_cycle(dep_id, nodes, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(dep_id) {
                    return true;
                }
            }
        }

        rec_stack.remove(node_id);
        false
    }

    /// Get all nodes in topological order.
    pub fn topological_sort(&self) -> Option<Vec<ProofId>> {
        // In-degree = number of dependencies each node has
        let mut in_degree: std::collections::HashMap<ProofId, usize> =
            self.nodes.keys().cloned().map(|id| (id, 0)).collect();

        // Calculate in-degrees based on dependencies
        for node in self.nodes.values() {
            in_degree.insert(node.id.clone(), node.dependencies.len());
        }

        // Start with nodes that have no dependencies
        let mut queue: Vec<ProofId> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut result = Vec::new();
        while let Some(node_id) = queue.pop() {
            result.push(node_id.clone());

            // Reduce in-degree for nodes that depend on this node
            for node in self.nodes.values() {
                if node.dependencies.contains(&node_id) {
                    if let Some(deg) = in_degree.get_mut(&node.id) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(node.id.clone());
                        }
                    }
                }
            }
        }

        if result.len() == self.nodes.len() {
            Some(result)
        } else {
            None
        }
    }

    /// Get the depth of the DAG (longest path from root).
    pub fn depth(&self) -> usize {
        let mut memo: std::collections::HashMap<ProofId, usize> = std::collections::HashMap::new();

        self.nodes
            .values()
            .filter(|n| n.dependencies.is_empty())
            .map(|root| Self::node_depth(root, &self.nodes, &mut memo))
            .max()
            .unwrap_or(0)
    }

    /// Calculate the depth of a node (longest path from this node to any leaf).
    fn node_depth(
        node: &ProofNode,
        nodes: &std::collections::HashMap<ProofId, ProofNode>,
        memo: &mut std::collections::HashMap<ProofId, usize>,
    ) -> usize {
        if let Some(&depth) = memo.get(&node.id) {
            return depth;
        }

        // Find all nodes that depend on this node (children in the dependency graph)
        let children: Vec<&ProofNode> = nodes
            .values()
            .filter(|n| n.dependencies.contains(&node.id))
            .collect();

        let depth = if children.is_empty() {
            // This node has no dependents, it's a leaf
            1
        } else {
            1 + children
                .iter()
                .map(|child| Self::node_depth(child, nodes, memo))
                .max()
                .unwrap_or(0)
        };

        memo.insert(node.id.clone(), depth);
        depth
    }

    /// Get the total number of proofs in the DAG.
    pub fn proof_count(&self) -> usize {
        self.nodes.len()
    }

    /// Verify all proofs in the DAG are valid (structural check).
    pub fn verify_structure(&self) -> bool {
        if !self.verify_acyclic() {
            return false;
        }

        for node in self.nodes.values() {
            for dep_id in &node.dependencies {
                if !self.nodes.contains_key(dep_id) {
                    return false;
                }
            }
        }

        true
    }
}
