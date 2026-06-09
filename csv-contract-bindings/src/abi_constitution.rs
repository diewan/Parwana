//! ABI Constitution for CSV Protocol Contracts
//!
//! This module defines the ABI constitution that all chain contracts MUST follow.
//! Uses canonical snake_case naming across all chains (Ethereum, Solana, Sui, Aptos).
//!
//! # ABI Constitution Requirements
//!
//! All CSV protocol contracts MUST:
//! 1. Emit canonical events with indexed parameters
//! 2. Use deterministic error codes
//! 3. Implement required functions with exact signatures (snake_case)
//! 4. Follow state machine invariants
//! 5. Support replay nullifier registration
//! 6. Anchor commitments with proof roots
//! 7. Use canonical SanadState enum (0-9 values)

use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// ABI constitution version.
pub const ABI_CONSTITUTION_VERSION: u32 = 2; // Updated to canonical snake_case naming

/// Maximum function name length (bytes).
pub const MAX_FUNCTION_NAME_LENGTH: usize = 32;

/// Maximum parameter count per function.
pub const MAX_PARAMETERS: usize = 10;

/// Required function signatures that all contracts MUST implement (canonical snake_case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredFunction {
    /// create_seal(sanad_id, commitment, state_root) -> bool
    CreateSeal,

    /// consume_seal(seal_id, nullifier) -> bool
    ConsumeSeal,

    /// lock_sanad(sanad_id, commitment, destination_chain, destination_owner) -> bool
    LockSanad,

    /// mint_sanad(sanad_id, commitment, state_root, source_chain, source_seal_ref, proof, proof_root, leaf_position) -> bool
    MintSanad,

    /// refund_sanad(sanad_id, destination_owner_hash) -> bool
    RefundSanad,

    /// transfer_sanad(sanad_id, new_owner) -> bool
    TransferSanad,

    /// register_nullifier(nullifier, sanad_id, source_chain) -> bool
    RegisterNullifier,

    /// anchor_commitment(commitment, seal_id) -> bool
    AnchorCommitment,

    /// record_sanad_metadata(sanad_id, asset_class, asset_id, metadata_hash, proof_system, proof_root) -> bool
    RecordSanadMetadata,

    /// update_proof_root(proof_root) -> bool
    UpdateProofRoot,

    /// get_sanad_state(sanad_id) -> SanadStateView
    GetSanadState,
}

impl RequiredFunction {
    /// Get the function signature as a string.
    pub fn signature(&self) -> &'static str {
        match self {
            RequiredFunction::CreateSeal => "create_seal(bytes32,bytes32,bytes32)",
            RequiredFunction::ConsumeSeal => "consume_seal(bytes32,bytes32)",
            RequiredFunction::LockSanad => "lock_sanad(bytes32,bytes32,uint8,bytes)",
            RequiredFunction::MintSanad => {
                "mint_sanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32,uint256)"
            }
            RequiredFunction::RefundSanad => "refund_sanad(bytes32,bytes32)",
            RequiredFunction::TransferSanad => "transfer_sanad(bytes32,address)",
            RequiredFunction::RegisterNullifier => "register_nullifier(bytes32,bytes32,uint8)",
            RequiredFunction::AnchorCommitment => "anchor_commitment(bytes32,bytes32)",
            RequiredFunction::RecordSanadMetadata => {
                "record_sanad_metadata(bytes32,uint8,bytes32,bytes32,uint8,bytes32)"
            }
            RequiredFunction::UpdateProofRoot => "update_proof_root(bytes32)",
            RequiredFunction::GetSanadState => "get_sanad_state(bytes32)",
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
            RequiredFunction::CreateSeal => 3,
            RequiredFunction::ConsumeSeal => 2,
            RequiredFunction::LockSanad => 4,
            RequiredFunction::MintSanad => 8,
            RequiredFunction::RefundSanad => 2,
            RequiredFunction::TransferSanad => 2,
            RequiredFunction::RegisterNullifier => 3,
            RequiredFunction::AnchorCommitment => 2,
            RequiredFunction::RecordSanadMetadata => 6,
            RequiredFunction::UpdateProofRoot => 1,
            RequiredFunction::GetSanadState => 1,
        }
    }
}

/// Canonical event names that all contracts MUST emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredEvent {
    /// Emitted when a seal is created
    SanadCreated,
    /// Emitted when a seal is consumed
    SanadConsumed,
    /// Emitted when a Sanad is locked for cross-chain transfer
    SanadLocked,
    /// Emitted when a Sanad is minted on destination chain
    SanadMinted,
    /// Emitted when a locked Sanad is refunded
    SanadRefunded,
    /// Emitted when Sanad ownership is transferred
    SanadTransferred,
    /// Emitted when a nullifier is registered
    NullifierRegistered,
    /// Emitted when a commitment is anchored
    CommitmentAnchored,
    /// Emitted when proof root is updated
    ProofRootUpdated,
    /// Emitted when replay is detected
    ReplayDetected,
}

impl RequiredEvent {
    /// Get the event name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            RequiredEvent::SanadCreated => "SanadCreated",
            RequiredEvent::SanadConsumed => "SanadConsumed",
            RequiredEvent::SanadLocked => "SanadLocked",
            RequiredEvent::SanadMinted => "SanadMinted",
            RequiredEvent::SanadRefunded => "SanadRefunded",
            RequiredEvent::SanadTransferred => "SanadTransferred",
            RequiredEvent::NullifierRegistered => "NullifierRegistered",
            RequiredEvent::CommitmentAnchored => "CommitmentAnchored",
            RequiredEvent::ProofRootUpdated => "ProofRootUpdated",
            RequiredEvent::ReplayDetected => "ReplayDetected",
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
                RequiredFunction::LockSanad,
                RequiredFunction::MintSanad,
                RequiredFunction::RefundSanad,
                RequiredFunction::TransferSanad,
                RequiredFunction::RegisterNullifier,
                RequiredFunction::AnchorCommitment,
                RequiredFunction::RecordSanadMetadata,
                RequiredFunction::UpdateProofRoot,
                RequiredFunction::GetSanadState,
            ],
            required_events: vec![
                "SanadCreated".to_string(),
                "SanadConsumed".to_string(),
                "SanadLocked".to_string(),
                "SanadMinted".to_string(),
                "SanadRefunded".to_string(),
                "SanadTransferred".to_string(),
                "NullifierRegistered".to_string(),
                "CommitmentAnchored".to_string(),
                "ProofRootUpdated".to_string(),
                "ReplayDetected".to_string(),
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
    /// Sanad not found (0x01)
    SanadNotFound = 0x01,
    /// Sanad already consumed (0x02)
    SanadAlreadyConsumed = 0x02,
    /// Sanad already locked (0x03)
    SanadAlreadyLocked = 0x03,
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
    /// Timeout not expired (0x0B)
    TimeoutNotExpired = 0x0B,
    /// Refund already claimed (0x0C)
    RefundAlreadyClaimed = 0x0C,
}

impl ErrorCode {
    /// Get the error code as a u8.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Get the error name.
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCode::SanadNotFound => "SanadNotFound",
            ErrorCode::SanadAlreadyConsumed => "SanadAlreadyConsumed",
            ErrorCode::SanadAlreadyLocked => "SanadAlreadyLocked",
            ErrorCode::InvalidCommitment => "InvalidCommitment",
            ErrorCode::InvalidProof => "InvalidProof",
            ErrorCode::NullifierAlreadyRegistered => "NullifierAlreadyRegistered",
            ErrorCode::InvalidProofRoot => "InvalidProofRoot",
            ErrorCode::Unauthorized => "Unauthorized",
            ErrorCode::InvalidChainId => "InvalidChainId",
            ErrorCode::RefundNotAvailable => "RefundNotAvailable",
            ErrorCode::TimeoutNotExpired => "TimeoutNotExpired",
            ErrorCode::RefundAlreadyClaimed => "RefundAlreadyClaimed",
        }
    }
}

/// Canonical Sanad lifecycle state — matches all chain contracts.
/// 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred, 7=Refunded, 8=Burned, 9=Invalid
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanadState {
    /// Sanad has not been created yet
    Uncreated = 0,
    /// Sanad has been created but not yet used
    Created = 1,
    /// Sanad is active and available for operations
    Active = 2,
    /// Sanad is locked for cross-chain transfer
    Locked = 3,
    /// Sanad has been consumed (single-use enforcement)
    Consumed = 4,
    /// Sanad has been minted on destination chain
    Minted = 5,
    /// Sanad ownership has been transferred
    Transferred = 6,
    /// Locked Sanad has been refunded
    Refunded = 7,
    /// Sanad has been burned (irreversible)
    Burned = 8,
    /// Invalid or unknown state
    Invalid = 9,
}

impl SanadState {
    /// Get the state name.
    pub fn name(&self) -> &'static str {
        match self {
            SanadState::Uncreated => "Uncreated",
            SanadState::Created => "Created",
            SanadState::Active => "Active",
            SanadState::Locked => "Locked",
            SanadState::Consumed => "Consumed",
            SanadState::Minted => "Minted",
            SanadState::Transferred => "Transferred",
            SanadState::Refunded => "Refunded",
            SanadState::Burned => "Burned",
            SanadState::Invalid => "Invalid",
        }
    }

    /// Get the state value.
    pub fn value(&self) -> u8 {
        *self as u8
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
    pub fn check_transition(&self, from_state: SanadState, to_state: SanadState) -> bool {
        matches!(
            (from_state, to_state),
            (SanadState::Created, SanadState::Consumed)
                | (SanadState::Created, SanadState::Locked)
                | (SanadState::Locked, SanadState::Minted)
                | (SanadState::Locked, SanadState::Refunded)
        )
    }
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
        assert!(invariants.check_transition(SanadState::Created, SanadState::Consumed));
        assert!(!invariants.check_transition(SanadState::Consumed, SanadState::Created));
    }

    #[test]
    fn test_canonical_state_values() {
        assert_eq!(SanadState::Uncreated.value(), 0);
        assert_eq!(SanadState::Created.value(), 1);
        assert_eq!(SanadState::Active.value(), 2);
        assert_eq!(SanadState::Locked.value(), 3);
        assert_eq!(SanadState::Consumed.value(), 4);
        assert_eq!(SanadState::Minted.value(), 5);
        assert_eq!(SanadState::Transferred.value(), 6);
        assert_eq!(SanadState::Refunded.value(), 7);
        assert_eq!(SanadState::Burned.value(), 8);
        assert_eq!(SanadState::Invalid.value(), 9);
    }
}
