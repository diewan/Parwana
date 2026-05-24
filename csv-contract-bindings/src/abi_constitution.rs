//! ABI Constitution for CSV Protocol Contracts
//!
//! This module defines the ABI constitution that all chain contracts MUST follow.
//! The constitution ensures contract equivalence across chains and enables
//! unified verification and indexing.
//!
//! # ABI Constitution Requirements
//!
//! All CSV protocol contracts MUST:
//! 1. Emit canonical events with indexed parameters
//! 2. Use deterministic error codes
//! 3. Implement required functions with exact signatures
//! 4. Follow state machine invariants
//! 5. Support replay nullifier registration
//! 6. Anchor commitments with proof roots
//!
//! # Required Functions
//!
//! Every chain contract MUST implement these functions:
//! - createSeal(bytes32 commitment) -> bytes32 sealId
//! - consumeSeal(bytes32 sealId) -> bool
//! - lockSeal(bytes32 sealId, uint8 destinationChain, bytes destinationOwner) -> bool
//! - mintSeal(bytes32 sealId, bytes32 commitment, uint8 sourceChain, bytes sourceSealRef, bytes proof, bytes32 proofRoot, uint256 leafPosition) -> bool
//! - refundSeal(bytes32 sealId) -> bool
//! - registerNullifier(bytes32 nullifier) -> bool
//! - updateProofRoot(bytes32 proofRoot) -> bool

use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// ABI constitution version.
pub const ABI_CONSTITUTION_VERSION: u32 = 1;

/// Maximum function name length (bytes).
pub const MAX_FUNCTION_NAME_LENGTH: usize = 32;

/// Maximum parameter count per function.
pub const MAX_PARAMETERS: usize = 10;

/// Required function signatures that all contracts MUST implement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredFunction {
    /// createSeal(bytes32 commitment) -> bytes32 sealId
    CreateSeal,

    /// consumeSeal(bytes32 sealId) -> bool
    ConsumeSeal,

    /// lockSeal(bytes32 sealId, uint8 destinationChain, bytes destinationOwner) -> bool
    LockSeal,

    /// mintSeal(bytes32 sealId, bytes32 commitment, uint8 sourceChain, bytes sourceSealRef, bytes proof, bytes32 proofRoot, uint256 leafPosition) -> bool
    MintSeal,

    /// refundSeal(bytes32 sealId) -> bool
    RefundSeal,

    /// registerNullifier(bytes32 nullifier) -> bool
    RegisterNullifier,

    /// updateProofRoot(bytes32 proofRoot) -> bool
    UpdateProofRoot,
}

impl RequiredFunction {
    /// Get the function signature as a string.
    pub fn signature(&self) -> &'static str {
        match self {
            RequiredFunction::CreateSeal => "createSeal(bytes32)",
            RequiredFunction::ConsumeSeal => "consumeSeal(bytes32)",
            RequiredFunction::LockSeal => "lockSeal(bytes32,uint8,bytes)",
            RequiredFunction::MintSeal => {
                "mintSeal(bytes32,bytes32,uint8,bytes,bytes,bytes32,uint256)"
            }
            RequiredFunction::RefundSeal => "refundSeal(bytes32)",
            RequiredFunction::RegisterNullifier => "registerNullifier(bytes32)",
            RequiredFunction::UpdateProofRoot => "updateProofRoot(bytes32)",
        }
    }

    /// Get the function selector (first 4 bytes of keccak256(signature)).
    pub fn selector(&self) -> [u8; 4] {
        let signature = self.signature();
        let hash = Hash::sha256(signature.as_bytes());
        let mut selector = [0u8; 4];
        let hash_bytes = hash.as_ref() as &[u8];
        selector.copy_from_slice(&hash_bytes[..4]);
        selector
    }

    /// Get the parameter count.
    pub fn param_count(&self) -> usize {
        match self {
            RequiredFunction::CreateSeal => 1,
            RequiredFunction::ConsumeSeal => 1,
            RequiredFunction::LockSeal => 3,
            RequiredFunction::MintSeal => 7,
            RequiredFunction::RefundSeal => 1,
            RequiredFunction::RegisterNullifier => 1,
            RequiredFunction::UpdateProofRoot => 1,
        }
    }
}

/// Contract ABI constitution compliance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiConstitution {
    /// Constitution version
    pub version: u32,
    /// Required functions
    pub required_functions: Vec<RequiredFunction>,
    /// Required events
    pub required_events: Vec<String>,
}

impl Default for AbiConstitution {
    fn default() -> Self {
        Self {
            version: ABI_CONSTITUTION_VERSION,
            required_functions: vec![
                RequiredFunction::CreateSeal,
                RequiredFunction::ConsumeSeal,
                RequiredFunction::LockSeal,
                RequiredFunction::MintSeal,
                RequiredFunction::RefundSeal,
                RequiredFunction::RegisterNullifier,
                RequiredFunction::UpdateProofRoot,
            ],
            required_events: vec![
                "SealCreated".to_string(),
                "SealConsumed".to_string(),
                "SealLocked".to_string(),
                "SealMinted".to_string(),
                "SealRefunded".to_string(),
                "CommitmentAnchored".to_string(),
                "ReplayNullifierRegistered".to_string(),
                "ProofRootUpdated".to_string(),
            ],
        }
    }
}

impl AbiConstitution {
    /// Create a new ABI constitution.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a contract ABI complies with the constitution.
    pub fn check_compliance(&self, contract_abi: &ContractAbi) -> ComplianceResult {
        let mut missing_functions = Vec::new();
        let mut missing_events = Vec::new();
        let mut invalid_signatures = Vec::new();

        // Check required functions
        for required_fn in &self.required_functions {
            if !contract_abi
                .functions
                .iter()
                .any(|f| f.name == required_fn.signature())
            {
                missing_functions.push(required_fn.signature().to_string());
            }
        }

        // Check required events
        for required_event in &self.required_events {
            if !contract_abi
                .events
                .iter()
                .any(|e| e.name == *required_event)
            {
                missing_events.push(required_event.clone());
            }
        }

        // Check function signatures
        for func in &contract_abi.functions {
            if let Some(required) = self
                .required_functions
                .iter()
                .find(|r| r.signature() == func.name)
                .filter(|required| func.param_count() != required.param_count())
            {
                let _ = required;
                invalid_signatures.push(func.name.clone());
            }
        }

        ComplianceResult {
            is_compliant: missing_functions.is_empty()
                && missing_events.is_empty()
                && invalid_signatures.is_empty(),
            missing_functions,
            missing_events,
            invalid_signatures,
        }
    }
}

/// Contract ABI representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAbi {
    /// Contract name
    pub name: String,
    /// Contract functions
    pub functions: Vec<FunctionAbi>,
    /// Contract events
    pub events: Vec<EventAbi>,
    /// Contract errors
    pub errors: Vec<ErrorAbi>,
}

/// Function ABI representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAbi {
    /// Function name
    pub name: String,
    /// Input parameters
    pub inputs: Vec<ParameterAbi>,
    /// Output parameters
    pub outputs: Vec<ParameterAbi>,
    /// Whether function is payable
    pub payable: bool,
}

impl FunctionAbi {
    /// Get the parameter count.
    pub fn param_count(&self) -> usize {
        self.inputs.len()
    }
}

/// Event ABI representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventAbi {
    /// Event name
    pub name: String,
    /// Indexed parameters (topics)
    pub indexed: Vec<ParameterAbi>,
    /// Non-indexed parameters (data)
    pub non_indexed: Vec<ParameterAbi>,
}

/// Parameter ABI representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterAbi {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub param_type: String,
    /// Whether parameter is indexed (for events)
    pub indexed: bool,
}

/// Error ABI representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorAbi {
    /// Error name
    pub name: String,
    /// Error parameters
    pub inputs: Vec<ParameterAbi>,
}

/// ABI compliance check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Whether the contract is compliant
    pub is_compliant: bool,
    /// Missing required functions
    pub missing_functions: Vec<String>,
    /// Missing required events
    pub missing_events: Vec<String>,
    /// Invalid function signatures
    pub invalid_signatures: Vec<String>,
}

/// Deterministic error codes that all contracts MUST use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Seal not found (0x01)
    SealNotFound = 0x01,
    /// Seal already consumed (0x02)
    SealAlreadyConsumed = 0x02,
    /// Seal already locked (0x03)
    SealAlreadyLocked = 0x03,
    /// Invalid commitment (0x04)
    InvalidCommitment = 0x04,
    /// Invalid proof (0x05)
    InvalidProof = 0x05,
    /// Nullifier already registered (0x06)
    NullifierAlreadyRegistered = 0x06,
    /// Invalid proof root (0x07)
    InvalidProofRoot = 0x07,
    /// Unauthorized caller (0x08)
    Unauthorized = 0x08,
    /// Invalid chain ID (0x09)
    InvalidChainId = 0x09,
    /// Refund not available (0x0A)
    RefundNotAvailable = 0x0A,
}

impl ErrorCode {
    /// Get the error code as a u8.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Get the error name.
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCode::SealNotFound => "SealNotFound",
            ErrorCode::SealAlreadyConsumed => "SealAlreadyConsumed",
            ErrorCode::SealAlreadyLocked => "SealAlreadyLocked",
            ErrorCode::InvalidCommitment => "InvalidCommitment",
            ErrorCode::InvalidProof => "InvalidProof",
            ErrorCode::NullifierAlreadyRegistered => "NullifierAlreadyRegistered",
            ErrorCode::InvalidProofRoot => "InvalidProofRoot",
            ErrorCode::Unauthorized => "Unauthorized",
            ErrorCode::InvalidChainId => "InvalidChainId",
            ErrorCode::RefundNotAvailable => "RefundNotAvailable",
        }
    }
}

/// State machine invariants that contracts MUST enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineInvariants {
    /// Seal can only be consumed once
    pub single_use_seal: bool,
    /// Seal cannot be locked if already consumed
    pub no_lock_after_consume: bool,
    /// Seal cannot be minted if nullifier already registered
    pub no_mint_with_replay: bool,
    /// Refund only available after timeout
    pub refund_only_after_timeout: bool,
    /// Proof root must be from trusted source
    pub trusted_proof_root: bool,
}

impl Default for StateMachineInvariants {
    fn default() -> Self {
        Self {
            single_use_seal: true,
            no_lock_after_consume: true,
            no_mint_with_replay: true,
            refund_only_after_timeout: true,
            trusted_proof_root: true,
        }
    }
}

impl StateMachineInvariants {
    /// Create new invariants.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a state transition is valid.
    pub fn check_transition(&self, from_state: SealState, to_state: SealState) -> bool {
        matches!(
            (from_state, to_state),
            (SealState::Created, SealState::Consumed)
                | (SealState::Created, SealState::Locked)
                | (SealState::Locked, SealState::Minted)
                | (SealState::Locked, SealState::Refunded)
        )
    }
}

/// Seal state in the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealState {
    /// Seal has been created but not yet used
    Created,
    /// Seal has been consumed (locked or burned)
    Consumed,
    /// Seal is locked for cross-chain transfer
    Locked,
    /// Seal has been minted from cross-chain transfer
    Minted,
    /// Seal has been refunded
    Refunded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_function_selector() {
        let func = RequiredFunction::CreateSeal;
        let selector = func.selector();
        assert_ne!(selector, [0u8; 4]);
    }

    #[test]
    fn test_abi_compliance_check() {
        let constitution = AbiConstitution::new();
        let contract_abi = ContractAbi {
            name: "TestContract".to_string(),
            functions: vec![],
            events: vec![],
            errors: vec![],
        };
        let result = constitution.check_compliance(&contract_abi);
        assert!(!result.is_compliant);
        assert!(!result.missing_functions.is_empty());
    }

    #[test]
    fn test_state_machine_invariants() {
        let invariants = StateMachineInvariants::new();
        assert!(invariants.check_transition(SealState::Created, SealState::Consumed));
        assert!(!invariants.check_transition(SealState::Consumed, SealState::Created));
    }
}
