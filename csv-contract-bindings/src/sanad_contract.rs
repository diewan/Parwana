//! Sanad contract bindings
//!
//! Type-safe bindings for the CSV Sanad contract deployed on each chain.
//! The sanad contract manages the content tree and rights transfer protocol.

use serde::{Serialize, Deserialize};
use crate::common::{ContractAddress, ContractAbi, FunctionSelector};

/// Sanad contract ABI (Ethereum-compatible)
pub const SANAD_CONTRACT_ABI: &str = r#"[
    {
        "type": "function",
        "name": "createSanad",
        "inputs": [
            {"name": "content_hash", "type": "bytes32"},
            {"name": "owner", "type": "address"},
            {"name": "metadata", "type": "bytes"}
        ],
        "outputs": [{"name": "sanad_id", "type": "bytes32"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "transferSanad",
        "inputs": [
            {"name": "sanad_id", "type": "bytes32"},
            {"name": "new_owner", "type": "address"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "getSanad",
        "inputs": [{"name": "sanad_id", "type": "bytes32"}],
        "outputs": [
            {"name": "content_hash", "type": "bytes32"},
            {"name": "owner", "type": "address"},
            {"name": "metadata", "type": "bytes"}
        ],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "SanadCreated",
        "inputs": [
            {"name": "sanad_id", "type": "bytes32", "indexed": true},
            {"name": "content_hash", "type": "bytes32", "indexed": true},
            {"name": "owner", "type": "address", "indexed": true}
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "SanadTransferred",
        "inputs": [
            {"name": "sanad_id", "type": "bytes32", "indexed": true},
            {"name": "from", "type": "address", "indexed": true},
            {"name": "to", "type": "address", "indexed": true}
        ],
        "anonymous": false
    }
]"#;

/// Sanad contract methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanadMethod {
    /// Create a new sanad
    CreateSanad,
    /// Transfer sanad ownership
    TransferSanad,
    /// Get sanad details
    GetSanad,
}

impl SanadMethod {
    /// Get the function selector for this method
    pub fn selector(&self) -> FunctionSelector {
        match self {
            Self::CreateSanad => FunctionSelector([0x00, 0x00, 0x00, 0x21]),
            Self::TransferSanad => FunctionSelector([0x00, 0x00, 0x00, 0x22]),
            Self::GetSanad => FunctionSelector([0x00, 0x00, 0x00, 0x23]),
        }
    }

    /// Get the method name
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateSanad => "createSanad",
            Self::TransferSanad => "transferSanad",
            Self::GetSanad => "getSanad",
        }
    }
}

/// Sanad created event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadCreatedEvent {
    /// Sanad ID
    pub sanad_id: [u8; 32],
    /// Content hash
    pub content_hash: [u8; 32],
    /// Owner address
    pub owner: Vec<u8>,
}

/// Sanad transferred event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadTransferredEvent {
    /// Sanad ID
    pub sanad_id: [u8; 32],
    /// From address
    pub from: Vec<u8>,
    /// To address
    pub to: Vec<u8>,
}

/// Sanad details
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadDetails {
    /// Content hash
    pub content_hash: [u8; 32],
    /// Owner address
    pub owner: Vec<u8>,
    /// Metadata
    pub metadata: Vec<u8>,
}

/// Sanad contract instance
#[derive(Debug, Clone)]
pub struct SanadContract {
    /// Contract address
    pub address: ContractAddress,
    /// Contract ABI
    pub abi: ContractAbi,
}

impl SanadContract {
    /// Create a new sanad contract instance
    pub fn new(address: ContractAddress) -> Self {
        let abi = ContractAbi::from_json(SANAD_CONTRACT_ABI)
            .expect("Sanad contract ABI must be valid JSON");
        Self { address, abi }
    }

    /// Get the sanad method selector
    pub fn method_selector(&self, method: SanadMethod) -> FunctionSelector {
        method.selector()
    }
}

impl Default for SanadContract {
    fn default() -> Self {
        Self::new(ContractAddress::new(vec![0u8; 20]))
    }
}
