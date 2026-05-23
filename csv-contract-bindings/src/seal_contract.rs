//! Seal contract bindings
//!
//! Type-safe bindings for the CSV Seal contract deployed on each chain.
//! The seal contract is responsible for:
//! - Registering new seals
//! - Verifying seal ownership
//! - Processing seal consumption

use serde::{Serialize, Deserialize};
use crate::common::{ContractAddress, ContractAbi, FunctionSelector};

/// Seal contract ABI (Ethereum-compatible)
pub const SEAL_CONTRACT_ABI: &str = r#"[
    {
        "type": "function",
        "name": "seal",
        "inputs": [
            {"name": "seal_id", "type": "bytes32"},
            {"name": "owner", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "proof", "type": "bytes"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "consume",
        "inputs": [
            {"name": "seal_id", "type": "bytes32"},
            {"name": "proof", "type": "bytes"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "ownerOf",
        "inputs": [{"name": "seal_id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "isSealActive",
        "inputs": [{"name": "seal_id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "SealCreated",
        "inputs": [
            {"name": "seal_id", "type": "bytes32", "indexed": true},
            {"name": "owner", "type": "address", "indexed": true},
            {"name": "amount", "type": "uint256", "indexed": false}
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "SealConsumed",
        "inputs": [
            {"name": "seal_id", "type": "bytes32", "indexed": true},
            {"name": "consumer", "type": "address", "indexed": true}
        ],
        "anonymous": false
    }
]"#;

/// Seal contract methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMethod {
    /// Seal a new asset
    Seal,
    /// Consume a seal
    Consume,
    /// Get seal owner
    OwnerOf,
    /// Check if seal is active
    IsSealActive,
}

impl SealMethod {
    /// Get the function selector for this method
    pub fn selector(&self) -> FunctionSelector {
        match self {
            Self::Seal => FunctionSelector([0x00, 0x00, 0x00, 0x01]),
            Self::Consume => FunctionSelector([0x00, 0x00, 0x00, 0x02]),
            Self::OwnerOf => FunctionSelector([0x00, 0x00, 0x00, 0x03]),
            Self::IsSealActive => FunctionSelector([0x00, 0x00, 0x00, 0x04]),
        }
    }

    /// Get the method name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Seal => "seal",
            Self::Consume => "consume",
            Self::OwnerOf => "ownerOf",
            Self::IsSealActive => "isSealActive",
        }
    }
}

/// Seal created event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealCreatedEvent {
    /// Seal ID
    pub seal_id: [u8; 32],
    /// Owner address
    pub owner: Vec<u8>,
    /// Amount
    pub amount: u128,
}

/// Seal consumed event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealConsumedEvent {
    /// Seal ID
    pub seal_id: [u8; 32],
    /// Consumer address
    pub consumer: Vec<u8>,
}

/// Seal contract instance
#[derive(Debug, Clone)]
pub struct SealContract {
    /// Contract address
    pub address: ContractAddress,
    /// Contract ABI
    pub abi: ContractAbi,
}

impl SealContract {
    /// Create a new seal contract instance
    pub fn new(address: ContractAddress) -> Self {
        let abi = ContractAbi::from_json(SEAL_CONTRACT_ABI)
            .expect("Seal contract ABI must be valid JSON");
        Self { address, abi }
    }

    /// Get the seal method selector
    pub fn method_selector(&self, method: SealMethod) -> FunctionSelector {
        method.selector()
    }

    /// Check if a seal is registered
    pub fn is_registered(&self, _seal_id: &[u8; 32]) -> bool {
        // This would call the contract in production
        false
    }
}

impl Default for SealContract {
    fn default() -> Self {
        Self::new(ContractAddress::new(vec![0u8; 20]))
    }
}
