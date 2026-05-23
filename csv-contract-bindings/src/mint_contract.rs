//! Mint contract bindings
//!
//! Type-safe bindings for the CSV Mint contract deployed on each chain.
//! The mint contract is responsible for:
//! - Minting new assets based on proof validation
//! - Managing the minting queue
//! - Handling minting failures and rollbacks

use serde::{Serialize, Deserialize};
use crate::common::{ContractAddress, ContractAbi, FunctionSelector};

/// Mint contract ABI (Ethereum-compatible)
pub const MINT_CONTRACT_ABI: &str = r#"[
    {
        "type": "function",
        "name": "mint",
        "inputs": [
            {"name": "proof_bundle", "type": "bytes"},
            {"name": "recipient", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "rollback",
        "inputs": [
            {"name": "transfer_id", "type": "bytes32"},
            {"name": "reason", "type": "string"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "getMintingStatus",
        "inputs": [{"name": "transfer_id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "Minted",
        "inputs": [
            {"name": "transfer_id", "type": "bytes32", "indexed": true},
            {"name": "recipient", "type": "address", "indexed": true},
            {"name": "amount", "type": "uint256", "indexed": false}
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "MintRollback",
        "inputs": [
            {"name": "transfer_id", "type": "bytes32", "indexed": true},
            {"name": "reason", "type": "string", "indexed": false}
        ],
        "anonymous": false
    }
]"#;

/// Mint contract methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintMethod {
    /// Mint a new asset
    Mint,
    /// Rollback a failed mint
    Rollback,
    /// Get minting status
    GetMintingStatus,
}

impl MintMethod {
    /// Get the function selector for this method
    pub fn selector(&self) -> FunctionSelector {
        match self {
            Self::Mint => FunctionSelector([0x00, 0x00, 0x00, 0x11]),
            Self::Rollback => FunctionSelector([0x00, 0x00, 0x00, 0x12]),
            Self::GetMintingStatus => FunctionSelector([0x00, 0x00, 0x00, 0x13]),
        }
    }

    /// Get the method name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Rollback => "rollback",
            Self::GetMintingStatus => "getMintingStatus",
        }
    }
}

/// Minting status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintingStatus {
    /// Not yet minted
    Pending = 0,
    /// Minting in progress
    InProgress = 1,
    /// Minted successfully
    Completed = 2,
    /// Mint failed, rollback required
    Failed = 3,
}

/// Minted event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedEvent {
    /// Transfer ID
    pub transfer_id: [u8; 32],
    /// Recipient address
    pub recipient: Vec<u8>,
    /// Amount minted
    pub amount: u128,
}

/// Mint rollback event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRollbackEvent {
    /// Transfer ID
    pub transfer_id: [u8; 32],
    /// Rollback reason
    pub reason: String,
}

/// Mint contract instance
#[derive(Debug, Clone)]
pub struct MintContract {
    /// Contract address
    pub address: ContractAddress,
    /// Contract ABI
    pub abi: ContractAbi,
}

impl MintContract {
    /// Create a new mint contract instance
    pub fn new(address: ContractAddress) -> Self {
        let abi = ContractAbi::from_json(MINT_CONTRACT_ABI)
            .expect("Mint contract ABI must be valid JSON");
        Self { address, abi }
    }

    /// Get the mint method selector
    pub fn method_selector(&self, method: MintMethod) -> FunctionSelector {
        method.selector()
    }
}

impl Default for MintContract {
    fn default() -> Self {
        Self::new(ContractAddress::new(vec![0u8; 20]))
    }
}
