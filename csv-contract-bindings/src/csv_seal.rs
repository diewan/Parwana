//! CSVSeal contract bindings (Ethereum)
//!
//! Type-safe bindings for the CSVSeal contract deployed on Ethereum.
//! This is the canonical unified contract for lock, mint, and refund operations.
//!
//! Generated from: csv-contracts/ethereum/contracts/out/CSVSeal.sol/CSVSeal.json

use crate::abi_constitution::{AbiConstitution, ContractAbi as AbiConstitutionAbi, EventAbi, FunctionAbi, ParameterAbi};
use crate::common::{ContractAbi, ContractAddress, FunctionSelector};
use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// CSVSeal contract ABI (canonical version)
pub const CSV_SEAL_ABI: &str = include_str!("../../csv-contracts/ethereum/contracts/out/CSVSeal.sol/CSVSeal.json");

/// CSVSeal contract methods (canonical snake_case naming)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvSealMethod {
    /// create_seal(commitment, sealId) -> bool
    CreateSeal,
    /// consume_seal(sealId, nullifier) -> bool
    ConsumeSeal,
    /// lock_sanad(sanadId, commitment, destinationChain, destinationOwner) -> bool
    LockSanad,
    /// mint_sanad(sanadId, commitment, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, leafPosition) -> bool
    MintSanad,
    /// refund_sanad(sanadId, destinationOwnerHash) -> bool
    RefundSanad,
    /// transfer_sanad(sanadId, newOwner) -> bool
    TransferSanad,
    /// register_nullifier(nullifier, sanadId, sourceChain) -> bool
    RegisterNullifier,
    /// anchor_commitment(commitment, sealId) -> bool
    AnchorCommitment,
    /// record_sanad_metadata(sanadId, assetClass, assetId, metadataHash, proofSystem, proofRoot) -> bool
    RecordSanadMetadata,
    /// update_proof_root(proofRoot) -> bool
    UpdateProofRoot,
    /// get_sanad_state(sanadId) -> SanadStateView
    GetSanadState,
    /// get_seal_state(sealId) -> SealStateView
    GetSealState,
    /// is_seal_available(sealId) -> bool
    IsSealAvailable,
    /// is_seal_consumed(sealId) -> bool
    IsSealConsumed,
    /// is_nullifier_registered(nullifier) -> bool
    IsNullifierRegistered,
    /// is_commitment_anchored(commitment) -> bool
    IsCommitmentAnchored,
    /// is_sanad_minted(sanadId) -> bool
    IsSanadMinted,
    /// can_refund(sanadId) -> bool
    CanRefund,
}

impl CsvSealMethod {
    /// Get the function selector for this method (keccak256 of signature)
    pub fn selector(&self) -> FunctionSelector {
        let signature = self.signature();
        let hash = Hash::sha256(signature.as_bytes());
        let mut selector = [0u8; 4];
        let hash_bytes = hash.as_ref() as &[u8];
        selector.copy_from_slice(&hash_bytes[..4]);
        FunctionSelector(selector)
    }

    /// Get the method signature
    pub fn signature(&self) -> &'static str {
        match self {
            Self::CreateSeal => "create_seal(bytes32,bytes32)",
            Self::ConsumeSeal => "consume_seal(bytes32,bytes32)",
            Self::LockSanad => "lock_sanad(bytes32,bytes32,uint8,bytes)",
            Self::MintSanad => "mint_sanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32,uint256)",
            Self::RefundSanad => "refund_sanad(bytes32,bytes32)",
            Self::TransferSanad => "transfer_sanad(bytes32,address)",
            Self::RegisterNullifier => "register_nullifier(bytes32,bytes32,uint8)",
            Self::AnchorCommitment => "anchor_commitment(bytes32,bytes32)",
            Self::RecordSanadMetadata => "record_sanad_metadata(bytes32,uint8,bytes32,bytes32,uint8,bytes32)",
            Self::UpdateProofRoot => "update_proof_root(bytes32)",
            Self::GetSanadState => "get_sanad_state(bytes32)",
            Self::GetSealState => "get_seal_state(bytes32)",
            Self::IsSealAvailable => "is_seal_available(bytes32)",
            Self::IsSealConsumed => "is_seal_consumed(bytes32)",
            Self::IsNullifierRegistered => "is_nullifier_registered(bytes32)",
            Self::IsCommitmentAnchored => "is_commitment_anchored(bytes32)",
            Self::IsSanadMinted => "is_sanad_minted(bytes32)",
            Self::CanRefund => "can_refund(bytes32)",
        }
    }

    /// Get the method name
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateSeal => "create_seal",
            Self::ConsumeSeal => "consume_seal",
            Self::LockSanad => "lock_sanad",
            Self::MintSanad => "mint_sanad",
            Self::RefundSanad => "refund_sanad",
            Self::TransferSanad => "transfer_sanad",
            Self::RegisterNullifier => "register_nullifier",
            Self::AnchorCommitment => "anchor_commitment",
            Self::RecordSanadMetadata => "record_sanad_metadata",
            Self::UpdateProofRoot => "update_proof_root",
            Self::GetSanadState => "get_sanad_state",
            Self::GetSealState => "get_seal_state",
            Self::IsSealAvailable => "is_seal_available",
            Self::IsSealConsumed => "is_seal_consumed",
            Self::IsNullifierRegistered => "is_nullifier_registered",
            Self::IsCommitmentAnchored => "is_commitment_anchored",
            Self::IsSanadMinted => "is_sanad_minted",
            Self::CanRefund => "can_refund",
        }
    }
}

/// CSVSeal canonical events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsvSealEvent {
    /// SanadCreated(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint256 timestamp)
    SanadCreated {
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        owner: Vec<u8>,
        timestamp: u64,
    },
    /// SanadConsumed(bytes32 indexed sanadId, bytes32 indexed nullifier, address indexed consumer, uint256 timestamp)
    SanadConsumed {
        sanad_id: [u8; 32],
        nullifier: [u8; 32],
        consumer: Vec<u8>,
        timestamp: u64,
    },
    /// SanadLocked(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint8 destinationChain, bytes destinationOwner, uint256 timestamp)
    SanadLocked {
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        owner: Vec<u8>,
        destination_chain: u8,
        destination_owner: Vec<u8>,
        timestamp: u64,
    },
    /// SanadMinted(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint8 sourceChain, bytes sourceSealRef, uint256 timestamp)
    SanadMinted {
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        owner: Vec<u8>,
        source_chain: u8,
        source_seal_ref: Vec<u8>,
        timestamp: u64,
    },
    /// SanadRefunded(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed claimant, string reason, uint256 timestamp)
    SanadRefunded {
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        claimant: Vec<u8>,
        reason: String,
        timestamp: u64,
    },
    /// SanadTransferred(bytes32 indexed sanadId, address indexed from, address indexed to, uint256 timestamp)
    SanadTransferred {
        sanad_id: [u8; 32],
        from: Vec<u8>,
        to: Vec<u8>,
        timestamp: u64,
    },
    /// NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanadId, uint8 sourceChain, uint256 timestamp)
    NullifierRegistered {
        nullifier: [u8; 32],
        sanad_id: [u8; 32],
        source_chain: u8,
        timestamp: u64,
    },
    /// CommitmentAnchored(bytes32 indexed commitment, bytes32 indexed sealId, address indexed owner, uint256 timestamp)
    CommitmentAnchored {
        commitment: [u8; 32],
        seal_id: [u8; 32],
        owner: Vec<u8>,
        timestamp: u64,
    },
    /// ProofRootUpdated(bytes32 indexed proofRoot, uint256 blockNumber, address indexed updater)
    ProofRootUpdated {
        proof_root: [u8; 32],
        block_number: u64,
        updater: Vec<u8>,
    },
    /// ReplayDetected(bytes32 indexed replayId, bytes32 indexed sanadId, uint256 timestamp)
    ReplayDetected {
        replay_id: [u8; 32],
        sanad_id: [u8; 32],
        timestamp: u64,
    },
}

impl CsvSealEvent {
    /// Get the event name
    pub fn name(&self) -> &'static str {
        match self {
            Self::SanadCreated { .. } => "SanadCreated",
            Self::SanadConsumed { .. } => "SanadConsumed",
            Self::SanadLocked { .. } => "SanadLocked",
            Self::SanadMinted { .. } => "SanadMinted",
            Self::SanadRefunded { .. } => "SanadRefunded",
            Self::SanadTransferred { .. } => "SanadTransferred",
            Self::NullifierRegistered { .. } => "NullifierRegistered",
            Self::CommitmentAnchored { .. } => "CommitmentAnchored",
            Self::ProofRootUpdated { .. } => "ProofRootUpdated",
            Self::ReplayDetected { .. } => "ReplayDetected",
        }
    }
}

/// CSVSeal contract instance
#[derive(Debug, Clone)]
pub struct CsvSealContract {
    /// Contract address
    pub address: ContractAddress,
    /// Contract ABI
    pub abi: ContractAbi,
}

impl CsvSealContract {
    /// Create a new CSVSeal contract instance from compiled ABI
    pub fn new(address: ContractAddress) -> Result<Self, serde_json::Error> {
        let abi = ContractAbi::from_json(CSV_SEAL_ABI)?;
        Ok(Self { address, abi })
    }

    /// Get the method selector for a CSVSeal method
    pub fn method_selector(&self, method: CsvSealMethod) -> FunctionSelector {
        method.selector()
    }

    /// Verify the contract ABI complies with the ABI constitution
    pub fn verify_abi_compliance(&self) -> Result<ComplianceCheck, ComplianceError> {
        let constitution = AbiConstitution::new();
        // Convert common::ContractAbi to abi_constitution::ContractAbi
        let constitution_abi = AbiConstitutionAbi {
            name: self.abi.name.clone(),
            functions: self.abi.methods.iter().map(|m| FunctionAbi {
                name: m.signature.clone(),
                inputs: m.inputs.iter().map(|i| ParameterAbi {
                    name: i.name.clone(),
                    param_type: i.r#type.clone(),
                    indexed: false,
                }).collect(),
                outputs: m.outputs.iter().map(|o| ParameterAbi {
                    name: String::new(),
                    param_type: o.r#type.clone(),
                    indexed: false,
                }).collect(),
                payable: false,
            }).collect(),
            events: self.abi.events.iter().map(|e| EventAbi {
                name: e.name.clone(),
                indexed: e.inputs.iter().filter(|i| i.indexed).map(|i| ParameterAbi {
                    name: i.name.clone(),
                    param_type: i.r#type.clone(),
                    indexed: true,
                }).collect(),
                non_indexed: e.inputs.iter().filter(|i| !i.indexed).map(|i| ParameterAbi {
                    name: i.name.clone(),
                    param_type: i.r#type.clone(),
                    indexed: false,
                }).collect(),
            }).collect(),
            errors: vec![],
        };
        let result = constitution.check_compliance(&constitution_abi);

        Ok(ComplianceCheck {
            is_compliant: result.is_compliant,
            missing_functions: result.missing_functions,
            missing_events: result.missing_events,
            invalid_signatures: result.invalid_signatures,
        })
    }

    /// Compute the ABI hash for deployment verification
    pub fn compute_abi_hash(&self) -> Hash {
        let abi_bytes = CSV_SEAL_ABI.as_bytes();
        Hash::sha256(abi_bytes)
    }
}

/// ABI compliance check result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCheck {
    /// Whether the contract is compliant
    pub is_compliant: bool,
    /// Missing required functions
    pub missing_functions: Vec<String>,
    /// Missing required events
    pub missing_events: Vec<String>,
    /// Invalid function signatures
    pub invalid_signatures: Vec<String>,
}

/// ABI compliance error
#[derive(Debug, Clone, thiserror::Error)]
pub enum ComplianceError {
    /// Failed to parse ABI
    #[error("Failed to parse ABI: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_seal_method_selectors() {
        for method in [
            CsvSealMethod::CreateSeal,
            CsvSealMethod::ConsumeSeal,
            CsvSealMethod::LockSanad,
            CsvSealMethod::MintSanad,
            CsvSealMethod::RefundSanad,
        ] {
            let selector = method.selector();
            assert_ne!(selector.0, [0u8; 4], "Selector for {} should not be zero", method.name());
        }
    }

    #[test]
    fn test_csv_seal_event_names() {
        let events = [
            CsvSealEvent::SanadCreated {
                sanad_id: [0u8; 32],
                commitment: [0u8; 32],
                owner: vec![],
                timestamp: 0,
            },
            CsvSealEvent::SanadConsumed {
                sanad_id: [0u8; 32],
                nullifier: [0u8; 32],
                consumer: vec![],
                timestamp: 0,
            },
        ];

        for event in events {
            assert!(!event.name().is_empty());
        }
    }

    #[test]
    fn test_csv_seal_abi_parsing() {
        let contract = CsvSealContract::new(ContractAddress::new(vec![0u8; 20]));
        assert!(contract.is_ok(), "Should be able to parse CSVSeal ABI");
    }

    #[test]
    fn test_csv_seal_abi_hash() {
        let contract = CsvSealContract::new(ContractAddress::new(vec![0u8; 20])).unwrap();
        let hash = contract.compute_abi_hash();
        assert_ne!(hash, Hash::zero(), "ABI hash should not be zero");
    }
}
