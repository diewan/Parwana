//! Chain capability model with traits per Phase 6
//!
//! This module defines the capability traits that chains must implement
//! to participate in the CSV protocol. This enables runtime to query
//! chain capabilities and adapt behavior accordingly.

use serde::{Deserialize, Serialize};
use crate::finality::{FinalityType, FinalityConfig};

/// Chain capability trait - all chains must implement this.
pub trait ChainCapability: std::fmt::Debug {
    /// Get the chain ID.
    fn chain_id(&self) -> &str;
    
    /// Get the chain name.
    fn chain_name(&self) -> &str;
    
    /// Get the finality type for this chain.
    fn finality_type(&self) -> FinalityType;
    
    /// Get the required confirmations for this chain.
    fn required_confirmations(&self) -> u64;
    
    /// Check if the chain supports SPV proofs.
    fn supports_spv(&self) -> bool;
    
    /// Check if the chain supports contract calls.
    fn supports_contracts(&self) -> bool;
    
    /// Check if the chain supports tapret commitments.
    fn supports_tapret(&self) -> bool;
    
    /// Get the maximum proof size for this chain.
    fn max_proof_size(&self) -> usize;
    
    /// Get the maximum transaction size for this chain.
    fn max_tx_size(&self) -> usize;
    
    /// Get the block time for this chain.
    fn block_time(&self) -> u64;
    
    /// Check if the chain supports reorg detection.
    fn supports_reorg_detection(&self) -> bool;
    
    /// Get the capability set for this chain.
    fn capabilities(&self) -> CapabilitySet;
}

/// Capability set for a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Chain ID
    pub chain_id: String,
    /// Supported capabilities
    pub capabilities: Vec<Capability>,
}

impl CapabilitySet {
    /// Create a new capability set.
    pub fn new(chain_id: String, capabilities: Vec<Capability>) -> Self {
        Self {
            chain_id,
            capabilities,
        }
    }

    /// Check if a capability is supported.
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Add a capability.
    pub fn add_capability(&mut self, capability: Capability) {
        if !self.has_capability(capability) {
            self.capabilities.push(capability);
        }
    }

    /// Remove a capability.
    pub fn remove_capability(&mut self, capability: Capability) {
        self.capabilities.retain(|c| c != &capability);
    }
}

/// Individual capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// SPV proof support
    SpvProofs,
    
    /// Contract call support
    ContractCalls,
    
    /// Tapret commitment support
    TapretCommitments,
    
    /// Reorg detection
    ReorgDetection,
    
    /// State proofs
    StateProofs,
    
    /// Receipt proofs
    ReceiptProofs,
    
    /// Event indexing
    EventIndexing,
    
    /// Account abstraction
    AccountAbstraction,
    
    /// ZK proof verification
    ZkProofVerification,
    
    /// Cross-chain messaging
    CrossChainMessaging,
}

/// Bitcoin chain capability implementation.
#[derive(Debug)]
pub struct BitcoinCapability;

impl ChainCapability for BitcoinCapability {
    fn chain_id(&self) -> &str {
        "bitcoin"
    }

    fn chain_name(&self) -> &str {
        "Bitcoin"
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Probabilistic
    }

    fn required_confirmations(&self) -> u64 {
        6
    }

    fn supports_spv(&self) -> bool {
        true
    }

    fn supports_contracts(&self) -> bool {
        false
    }

    fn supports_tapret(&self) -> bool {
        true
    }

    fn max_proof_size(&self) -> usize {
        64 * 1024 // 64KB
    }

    fn max_tx_size(&self) -> usize {
        4 * 1024 * 1024 // 4MB
    }

    fn block_time(&self) -> u64 {
        600 // 10 minutes
    }

    fn supports_reorg_detection(&self) -> bool {
        true
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(
            "bitcoin".to_string(),
            vec![
                Capability::SpvProofs,
                Capability::TapretCommitments,
                Capability::ReorgDetection,
            ],
        )
    }
}

/// Ethereum chain capability implementation.
#[derive(Debug)]
pub struct EthereumCapability;

impl ChainCapability for EthereumCapability {
    fn chain_id(&self) -> &str {
        "ethereum"
    }

    fn chain_name(&self) -> &str {
        "Ethereum"
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Economic
    }

    fn required_confirmations(&self) -> u64 {
        2
    }

    fn supports_spv(&self) -> bool {
        false
    }

    fn supports_contracts(&self) -> bool {
        true
    }

    fn supports_tapret(&self) -> bool {
        false
    }

    fn max_proof_size(&self) -> usize {
        64 * 1024 // 64KB
    }

    fn max_tx_size(&self) -> usize {
        128 * 1024 // 128KB
    }

    fn block_time(&self) -> u64 {
        12 // 12 seconds
    }

    fn supports_reorg_detection(&self) -> bool {
        true
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(
            "ethereum".to_string(),
            vec![
                Capability::ContractCalls,
                Capability::ReceiptProofs,
                Capability::EventIndexing,
                Capability::AccountAbstraction,
                Capability::ReorgDetection,
            ],
        )
    }
}

/// Solana chain capability implementation.
#[derive(Debug)]
pub struct SolanaCapability;

impl ChainCapability for SolanaCapability {
    fn chain_id(&self) -> &str {
        "solana"
    }

    fn chain_name(&self) -> &str {
        "Solana"
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Quorum
    }

    fn required_confirmations(&self) -> u64 {
        1
    }

    fn supports_spv(&self) -> bool {
        false
    }

    fn supports_contracts(&self) -> bool {
        true
    }

    fn supports_tapret(&self) -> bool {
        false
    }

    fn max_proof_size(&self) -> usize {
        64 * 1024 // 64KB
    }

    fn max_tx_size(&self) -> usize {
        1232 * 1024 // 1232KB
    }

    fn block_time(&self) -> u64 {
        400 // ~400ms
    }

    fn supports_reorg_detection(&self) -> bool {
        true
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(
            "solana".to_string(),
            vec![
                Capability::ContractCalls,
                Capability::ReceiptProofs,
                Capability::EventIndexing,
                Capability::ZkProofVerification,
                Capability::ReorgDetection,
            ],
        )
    }
}

/// Sui chain capability implementation.
#[derive(Debug)]
pub struct SuiCapability;

impl ChainCapability for SuiCapability {
    fn chain_id(&self) -> &str {
        "sui"
    }

    fn chain_name(&self) -> &str {
        "Sui"
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }

    fn supports_spv(&self) -> bool {
        false
    }

    fn supports_contracts(&self) -> bool {
        true
    }

    fn supports_tapret(&self) -> bool {
        false
    }

    fn max_proof_size(&self) -> usize {
        64 * 1024 // 64KB
    }

    fn max_tx_size(&self) -> usize {
        256 * 1024 // 256KB
    }

    fn block_time(&self) -> u64 {
        2 // ~2 seconds
    }

    fn supports_reorg_detection(&self) -> bool {
        true
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(
            "sui".to_string(),
            vec![
                Capability::ContractCalls,
                Capability::StateProofs,
                Capability::EventIndexing,
                Capability::ZkProofVerification,
                Capability::ReorgDetection,
            ],
        )
    }
}

/// Aptos chain capability implementation.
#[derive(Debug)]
pub struct AptosCapability;

impl ChainCapability for AptosCapability {
    fn chain_id(&self) -> &str {
        "aptos"
    }

    fn chain_name(&self) -> &str {
        "Aptos"
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }

    fn supports_spv(&self) -> bool {
        false
    }

    fn supports_contracts(&self) -> bool {
        true
    }

    fn supports_tapret(&self) -> bool {
        false
    }

    fn max_proof_size(&self) -> usize {
        64 * 1024 // 64KB
    }

    fn max_tx_size(&self) -> usize {
        256 * 1024 // 256KB
    }

    fn block_time(&self) -> u64 {
        2 // ~2 seconds
    }

    fn supports_reorg_detection(&self) -> bool {
        true
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(
            "aptos".to_string(),
            vec![
                Capability::ContractCalls,
                Capability::StateProofs,
                Capability::EventIndexing,
                Capability::ReorgDetection,
            ],
        )
    }
}

/// Chain capability registry for querying chain capabilities.
#[derive(Debug, Default)]
pub struct ChainCapabilityRegistry {
    /// Registered chain capabilities
    pub chains: std::collections::HashMap<String, Box<dyn ChainCapability>>,
}

impl ChainCapabilityRegistry {
    /// Create a new chain capability registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a chain capability.
    pub fn register(&mut self, capability: Box<dyn ChainCapability>) {
        self.chains.insert(capability.chain_id().to_string(), capability);
    }

    /// Get a chain capability by ID.
    pub fn get(&self, chain_id: &str) -> Option<&Box<dyn ChainCapability>> {
        self.chains.get(chain_id)
    }

    /// Check if a chain supports a specific capability.
    pub fn supports_capability(&self, chain_id: &str, capability: Capability) -> bool {
        self.get(chain_id)
            .map(|c| c.capabilities().has_capability(capability))
            .unwrap_or(false)
    }

    /// Get all chains that support a specific capability.
    pub fn get_chains_with_capability(&self, capability: Capability) -> Vec<String> {
        self.chains
            .iter()
            .filter(|(_, c)| c.capabilities().has_capability(capability))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Initialize with all known chains.
    pub fn initialize_with_known_chains(&mut self) {
        self.register(Box::new(BitcoinCapability));
        self.register(Box::new(EthereumCapability));
        self.register(Box::new(SolanaCapability));
        self.register(Box::new(SuiCapability));
        self.register(Box::new(AptosCapability));
    }
}

/// Chain compatibility check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityResult {
    /// Whether chains are compatible
    pub is_compatible: bool,
    /// Missing capabilities
    pub missing_capabilities: Vec<Capability>,
    /// Capability mismatches
    pub capability_mismatches: Vec<String>,
}

/// Check compatibility between two chains for cross-chain transfer.
pub fn check_chain_compatibility(
    source_chain: &str,
    destination_chain: &str,
    registry: &ChainCapabilityRegistry,
) -> CompatibilityResult {
    let source = match registry.get(source_chain) {
        Some(c) => c,
        None => {
            return CompatibilityResult {
                is_compatible: false,
                missing_capabilities: vec![],
                capability_mismatches: vec![format!("Source chain {} not found", source_chain)],
            }
        }
    };

    let dest = match registry.get(destination_chain) {
        Some(c) => c,
        None => {
            return CompatibilityResult {
                is_compatible: false,
                missing_capabilities: vec![],
                capability_mismatches: vec![format!("Destination chain {} not found", destination_chain)],
            }
        }
    };

    // Check if both chains support required capabilities
    let required_capabilities = vec![
        Capability::ReorgDetection,
    ];

    let mut missing_capabilities = Vec::new();
    let mut capability_mismatches = Vec::new();

    for capability in required_capabilities {
        if !source.capabilities().has_capability(capability) {
            missing_capabilities.push(capability);
        }
        if !dest.capabilities().has_capability(capability) {
            missing_capabilities.push(capability);
        }
    }

    // Check if finality types are compatible
    if source.finality_type() != dest.finality_type() {
        capability_mismatches.push(format!(
            "Finality type mismatch: source {:?} vs dest {:?}",
            source.finality_type(),
            dest.finality_type()
        ));
    }

    let is_compatible = missing_capabilities.is_empty() && capability_mismatches.is_empty();

    CompatibilityResult {
        is_compatible,
        missing_capabilities,
        capability_mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_capability() {
        let bitcoin = BitcoinCapability;
        assert_eq!(bitcoin.chain_id(), "bitcoin");
        assert_eq!(bitcoin.finality_type(), FinalityType::Probabilistic);
        assert!(bitcoin.supports_spv());
        assert!(bitcoin.supports_tapret());
        assert!(!bitcoin.supports_contracts());
    }

    #[test]
    fn test_ethereum_capability() {
        let ethereum = EthereumCapability;
        assert_eq!(ethereum.chain_id(), "ethereum");
        assert_eq!(ethereum.finality_type(), FinalityType::Economic);
        assert!(!ethereum.supports_spv());
        assert!(ethereum.supports_contracts());
        assert!(!ethereum.supports_tapret());
    }

    #[test]
    fn test_capability_set() {
        let mut set = CapabilitySet::new("test".to_string(), vec![Capability::SpvProofs]);
        assert!(set.has_capability(Capability::SpvProofs));
        assert!(!set.has_capability(Capability::ContractCalls));
        
        set.add_capability(Capability::ContractCalls);
        assert!(set.has_capability(Capability::ContractCalls));
    }

    #[test]
    fn test_chain_capability_registry() {
        let mut registry = ChainCapabilityRegistry::new();
        registry.initialize_with_known_chains();
        
        assert!(registry.get("bitcoin").is_some());
        assert!(registry.get("ethereum").is_some());
        
        assert!(registry.supports_capability("bitcoin", Capability::SpvProofs));
        assert!(!registry.supports_capability("bitcoin", Capability::ContractCalls));
    }

    #[test]
    fn test_chain_compatibility() {
        let mut registry = ChainCapabilityRegistry::new();
        registry.initialize_with_known_chains();
        
        let result = check_chain_compatibility("bitcoin", "ethereum", &registry);
        // Should have finality type mismatch
        assert!(!result.is_compatible);
    }

    #[test]
    fn test_same_chain_compatibility() {
        let mut registry = ChainCapabilityRegistry::new();
        registry.initialize_with_known_chains();
        
        let result = check_chain_compatibility("ethereum", "ethereum", &registry);
        // Same chain should be compatible
        assert!(result.is_compatible);
    }
}
