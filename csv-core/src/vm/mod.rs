//! Deterministic VM (Phase 3) - Experimental feature
//!
//! This module provides a deterministic virtual machine for executing
//! CSV state transitions in a sandboxed environment.

use crate::state::{GlobalState, Metadata, OwnedState};

/// VM inputs for state transition execution.
#[derive(Debug, Clone)]
pub struct VMInputs {
    /// Owned state inputs
    pub owned_inputs: Vec<OwnedState>,
    /// Global state updates
    pub global_state: Vec<GlobalState>,
    /// Transition metadata
    pub metadata: Vec<Metadata>,
    /// Contract ID
    pub contract_id: Vec<u8>,
}

impl VMInputs {
    /// Create new VM inputs.
    pub fn new(
        owned_inputs: Vec<OwnedState>,
        global_state: Vec<GlobalState>,
        metadata: Vec<Metadata>,
        contract_id: Vec<u8>,
    ) -> Self {
        Self {
            owned_inputs,
            global_state,
            metadata,
            contract_id,
        }
    }
}

impl Default for VMInputs {
    fn default() -> Self {
        Self {
            owned_inputs: Vec::new(),
            global_state: Vec::new(),
            metadata: Vec::new(),
            contract_id: Vec::new(),
        }
    }
}

/// VM outputs from state transition execution.
#[derive(Debug, Clone, Default)]
pub struct VMOutputs {
    /// Output data
    pub data: Vec<u8>,
    /// New state hash
    pub state_hash: [u8; 32],
}

/// Deterministic VM trait for state transition execution.
pub trait DeterministicVM {
    /// Execute a validation script with the given inputs and signatures.
    fn execute(
        &mut self,
        script: &[u8],
        inputs: VMInputs,
        signatures: &[Vec<u8>],
    ) -> Result<VMOutputs, VMError>;

    /// Validate that outputs are consistent with inputs.
    fn validate_outputs(&self, _inputs: &VMInputs, _outputs: &VMOutputs) -> Result<(), VMError> {
        Ok(())
    }

    /// Get the current state hash.
    fn state_hash(&self) -> [u8; 32];

    /// Get the number of cycles consumed.
    fn cycles_consumed(&self) -> u64;
}

/// VM error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VMError {
    /// Execution exceeded cycle limit
    CycleLimitExceeded,
    /// Invalid transition data
    InvalidInput,
    /// State transition failed
    TransitionFailed,
    /// VM internal error
    InternalError,
}

impl std::fmt::Display for VMError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VMError::CycleLimitExceeded => write!(f, "VM cycle limit exceeded"),
            VMError::InvalidInput => write!(f, "Invalid VM input"),
            VMError::TransitionFailed => write!(f, "State transition failed"),
            VMError::InternalError => write!(f, "VM internal error"),
        }
    }
}

impl std::error::Error for VMError {}

/// Alu VM adapter for executing CSV state transitions.
#[derive(Debug, Clone, Default)]
pub struct AluVmAdapter {
    max_cycles: u64,
    cycles_consumed: u64,
}

impl AluVmAdapter {
    /// Create a new Alu VM adapter with the given cycle limit.
    pub fn new(max_cycles: u64) -> Self {
        Self {
            max_cycles,
            cycles_consumed: 0,
        }
    }

    /// Create a new Alu VM adapter with the default cycle limit.
    pub fn default_() -> Self {
        Self {
            max_cycles: 1_000_000,
            cycles_consumed: 0,
        }
    }
}

impl DeterministicVM for AluVmAdapter {
    fn execute(
        &mut self,
        _script: &[u8],
        _inputs: VMInputs,
        _signatures: &[Vec<u8>],
    ) -> Result<VMOutputs, VMError> {
        // Stub implementation - returns a deterministic output
        self.cycles_consumed += 1;
        if self.cycles_consumed > self.max_cycles {
            return Err(VMError::CycleLimitExceeded);
        }
        Ok(VMOutputs {
            data: Vec::new(),
            state_hash: [0u8; 32],
        })
    }

    fn validate_outputs(&self, _inputs: &VMInputs, _outputs: &VMOutputs) -> Result<(), VMError> {
        Ok(())
    }

    fn state_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }

    fn cycles_consumed(&self) -> u64 {
        self.cycles_consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_inputs_creation() {
        let inputs = VMInputs::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![1, 2, 3],
        );
        assert_eq!(inputs.contract_id, vec![1, 2, 3]);
    }

    #[test]
    fn test_alu_vm_adapter() {
        let mut vm = AluVmAdapter::new(1000);
        let inputs = VMInputs::default();
        let result = vm.execute(&[], inputs, &[]);
        assert!(result.is_ok());
        assert_eq!(vm.cycles_consumed(), 1);
    }

    #[test]
    fn test_alu_vm_cycle_limit() {
        let mut vm = AluVmAdapter::new(2);
        let inputs = VMInputs::default();
        vm.execute(&[], inputs.clone(), &[]).unwrap();
        vm.execute(&[], inputs.clone(), &[]).unwrap();
        vm.execute(&[], inputs.clone(), &[]).unwrap();
        assert!(vm.execute(&[], inputs, &[]).is_err());
    }
}
