//! CSV Lock Contract Bindings
//!
//! Type-safe bindings for the CSV Lock contract using Alloy.
//! Generated from CSVLock.sol

#![allow(clippy::too_many_arguments)]

use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_sol_types::sol;

// Solidity contract ABI
sol! {
    #[sol(rpc)]
    contract CSVLock {
        uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
        uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
        uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
        uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
        uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

        struct SanadMetadata {
            uint8 assetClass;
            bytes32 assetId;
            bytes32 metadataHash;
            uint8 proofSystem;
            bytes32 proofRoot;
        }

        struct LockRecord {
            bytes32 commitment;
            uint256 timestamp;
            uint8 destinationChain;
            bytes32 destinationOwnerRoot;
            SanadMetadata metadata;
            bool refunded;
        }

        uint256 public constant REFUND_TIMEOUT = 24 hours;
        address public immutable mintContract;

        event CrossChainLock(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed owner,
            bytes32 destinationChain,
            bytes destinationOwner,
            uint256 timestamp
        );

        event SealUsed(bytes32 indexed sealId, bytes32 commitment);

        event SanadRefunded(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed claimant,
            uint256 refundTimestamp
        );

        event SanadMetadataRecorded(
            bytes32 indexed sanadId,
            uint8 assetClass,
            bytes32 indexed assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 indexed proofRoot
        );

        error SanadAlreadyConsumed();
        error SanadAlreadyLocked();
        error TimeoutNotExpired();
        error SanadAlreadyMinted();
        error RefundAlreadyClaimed();
        error InvalidMintContract();
        error InvalidSanadMetadata();

        constructor(address _mintContract);

        function lockSanad(
            bytes32 sanadId,
            bytes32 commitment,
            uint8 destinationChain,
            bytes calldata destinationOwner
        ) external;

        function lockSanadWithMetadata(
            bytes32 sanadId,
            bytes32 commitment,
            uint8 destinationChain,
            bytes calldata destinationOwner,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 proofRoot
        ) external;

        function markSealUsed(bytes32 sealId, bytes32 commitment) external;

        function refundSanad(bytes32 sanadId, bytes32 destinationOwnerHash) external;

        function isSealUsed(bytes32 sealId) external view returns (bool);

        function getLockInfo(bytes32 sanadId) external view returns (
            bytes32 commitment,
            uint256 timestamp,
            uint8 destinationChain,
            bool refunded
        );

        function getSanadMetadata(bytes32 sanadId) external view returns (
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 proofRoot
        );

        function canRefund(bytes32 sanadId) external view returns (bool);
    }
}

/// CSV Lock contract interface
pub struct CsvLockClient {
    /// Contract address
    pub address: Address,
}

impl CsvLockClient {
    /// Create a new CSV Lock contract reference
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    /// Get the contract address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Create a lockSanad call
    pub fn lock_sanad_call(
        &self,
        sanad_id: FixedBytes<32>,
        commitment: FixedBytes<32>,
        destination_chain: u8,
        destination_owner: Bytes,
    ) -> CSVLock::lockSanadCall {
        CSVLock::lockSanadCall {
            sanadId: sanad_id,
            commitment,
            destinationChain: destination_chain,
            destinationOwner: destination_owner,
        }
    }

    /// Create a lockSanadWithMetadata call
    pub fn lock_sanad_with_metadata_call(
        &self,
        sanad_id: FixedBytes<32>,
        commitment: FixedBytes<32>,
        destination_chain: u8,
        destination_owner: Bytes,
        asset_class: u8,
        asset_id: FixedBytes<32>,
        metadata_hash: FixedBytes<32>,
        proof_system: u8,
        proof_root: FixedBytes<32>,
    ) -> CSVLock::lockSanadWithMetadataCall {
        CSVLock::lockSanadWithMetadataCall {
            sanadId: sanad_id,
            commitment,
            destinationChain: destination_chain,
            destinationOwner: destination_owner,
            assetClass: asset_class,
            assetId: asset_id,
            metadataHash: metadata_hash,
            proofSystem: proof_system,
            proofRoot: proof_root,
        }
    }

    /// Create a refundSanad call
    pub fn refund_sanad_call(
        &self,
        sanad_id: FixedBytes<32>,
        destination_owner_hash: FixedBytes<32>,
    ) -> CSVLock::refundSanadCall {
        CSVLock::refundSanadCall {
            sanadId: sanad_id,
            destinationOwnerHash: destination_owner_hash,
        }
    }

    /// Create an isSealUsed call
    pub fn is_seal_used_call(&self, seal_id: FixedBytes<32>) -> CSVLock::isSealUsedCall {
        CSVLock::isSealUsedCall { sealId: seal_id }
    }

    /// Create a getLockInfo call
    pub fn get_lock_info_call(&self, sanad_id: FixedBytes<32>) -> CSVLock::getLockInfoCall {
        CSVLock::getLockInfoCall { sanadId: sanad_id }
    }

    /// Create a canRefund call
    pub fn can_refund_call(&self, sanad_id: FixedBytes<32>) -> CSVLock::canRefundCall {
        CSVLock::canRefundCall { sanadId: sanad_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_csv_lock_creation() {
        let addr = address!("0000000000000000000000000000000000000001");
        let lock = CsvLockClient::new(addr);
        assert_eq!(lock.address(), addr);
    }

    #[test]
    fn test_lock_sanad_call() {
        let addr = address!("0000000000000000000000000000000000000001");
        let lock = CsvLockClient::new(addr);

        let sanad_id = FixedBytes::<32>::ZERO;
        let commitment = FixedBytes::<32>::ZERO;
        let destination_chain = 1u8;
        let destination_owner = Bytes::default();

        let call = lock.lock_sanad_call(sanad_id, commitment, destination_chain, destination_owner);
        assert_eq!(call.sanadId, sanad_id);
    }
}
