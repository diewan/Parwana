//! CSV Mint Contract Bindings
//!
//! Type-safe bindings for the CSV Mint contract using Alloy.
//! Generated from CSVMint.sol

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::sol;

// Solidity contract ABI
sol! {
    #[sol(rpc)]
    contract CSVMint {
        uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
        uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
        uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
        uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
        uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

        address public immutable lockContract;
        address public immutable verifier;

        struct SanadMetadata {
            uint8 assetClass;
            bytes32 assetId;
            bytes32 metadataHash;
            uint8 proofSystem;
            bytes32 proofRoot;
        }

        uint8 public constant CHAIN_BITCOIN = 0;
        uint8 public constant CHAIN_SUI = 1;
        uint8 public constant CHAIN_APTOS = 2;
        uint8 public constant CHAIN_ETHEREUM = 3;

        event SanadMinted(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed owner,
            uint8 sourceChain,
            bytes sourceSealPoint,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 proofRoot
        );

        event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanadId);

        event SanadMetadataRecorded(
            bytes32 indexed sanadId,
            uint8 assetClass,
            bytes32 indexed assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 indexed proofRoot
        );

        error SanadAlreadyMinted();
        error InvalidProof();
        error NullifierAlreadyRegistered();
        error ZeroAddress();
        error ArraysMismatch();
        error InvalidSanadMetadata();

        constructor(address _lockContract, address _verifier);

        function registerNullifier(bytes32 nullifier, bytes32 sanadId) external;

        function mintSanad(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 stateRoot,
            uint8 sourceChain,
            bytes calldata sourceSealPoint,
            bytes calldata proof,
            bytes32 proofRoot,
            uint256 leaf_position
        ) external returns (bool);

        function mintSanadWithMetadata(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 stateRoot,
            uint8 sourceChain,
            bytes calldata sourceSealPoint,
            bytes calldata proof,
            bytes32 proofRoot,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            uint256 leaf_position
        ) external returns (bool);

        function isSanadMinted(bytes32 sanadId) external view returns (bool);

        function isNullifierRegistered(bytes32 nullifier) external view returns (bool);

        function batchMintSanads(
            bytes32[] calldata sanadIds,
            bytes32[] calldata commitments,
            bytes32[] calldata stateRoots,
            uint8 sourceChain,
            bytes calldata sourceSealPoint,
            bytes[] calldata proofs,
            bytes32 proofRoot,
            uint256[] calldata leaf_positions
        ) external;
    }
}

/// CSV Mint contract interface
pub struct CsvMintClient {
    /// Contract address
    pub address: Address,
}

impl CsvMintClient {
    /// Create a new CSV Mint contract reference
    pub fn new(address: Address) -> Self {
        Self { address }
    }

    /// Get the contract address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Create a registerNullifier call
    pub fn register_nullifier_call(
        &self,
        nullifier: FixedBytes<32>,
        sanad_id: FixedBytes<32>,
    ) -> CSVMint::registerNullifierCall {
        CSVMint::registerNullifierCall {
            nullifier,
            sanadId: sanad_id,
        }
    }

    /// Create a mintSanad call
    pub fn mint_sanad_call(
        &self,
        sanad_id: FixedBytes<32>,
        commitment: FixedBytes<32>,
        state_root: FixedBytes<32>,
        source_chain: u8,
        source_seal_point: Bytes,
        proof: Bytes,
        proof_root: FixedBytes<32>,
        leaf_position: U256,
    ) -> CSVMint::mintSanadCall {
        CSVMint::mintSanadCall {
            sanadId: sanad_id,
            commitment,
            stateRoot: state_root,
            sourceChain: source_chain,
            sourceSealPoint: source_seal_point,
            proof,
            proofRoot: proof_root,
            leaf_position,
        }
    }

    /// Create a mintSanadWithMetadata call
    pub fn mint_sanad_with_metadata_call(
        &self,
        sanad_id: FixedBytes<32>,
        commitment: FixedBytes<32>,
        state_root: FixedBytes<32>,
        source_chain: u8,
        source_seal_point: Bytes,
        proof: Bytes,
        proof_root: FixedBytes<32>,
        asset_class: u8,
        asset_id: FixedBytes<32>,
        metadata_hash: FixedBytes<32>,
        proof_system: u8,
        leaf_position: U256,
    ) -> CSVMint::mintSanadWithMetadataCall {
        CSVMint::mintSanadWithMetadataCall {
            sanadId: sanad_id,
            commitment,
            stateRoot: state_root,
            sourceChain: source_chain,
            sourceSealPoint: source_seal_point,
            proof,
            proofRoot: proof_root,
            assetClass: asset_class,
            assetId: asset_id,
            metadataHash: metadata_hash,
            proofSystem: proof_system,
            leaf_position,
        }
    }

    /// Create an isSanadMinted call
    pub fn is_sanad_minted_call(&self, sanad_id: FixedBytes<32>) -> CSVMint::isSanadMintedCall {
        CSVMint::isSanadMintedCall { sanadId: sanad_id }
    }

    /// Create an isNullifierRegistered call
    pub fn is_nullifier_registered_call(
        &self,
        nullifier: FixedBytes<32>,
    ) -> CSVMint::isNullifierRegisteredCall {
        CSVMint::isNullifierRegisteredCall { nullifier }
    }

    /// Create a batchMintSanads call
    pub fn batch_mint_sanads_call(
        &self,
        sanad_ids: Vec<FixedBytes<32>>,
        commitments: Vec<FixedBytes<32>>,
        state_roots: Vec<FixedBytes<32>>,
        source_chain: u8,
        source_seal_point: Bytes,
        proofs: Vec<Bytes>,
        proof_root: FixedBytes<32>,
        leaf_positions: Vec<U256>,
    ) -> CSVMint::batchMintSanadsCall {
        CSVMint::batchMintSanadsCall {
            sanadIds: sanad_ids,
            commitments,
            stateRoots: state_roots,
            sourceChain: source_chain,
            sourceSealPoint: source_seal_point,
            proofs,
            proofRoot: proof_root,
            leaf_positions: leaf_positions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_mint_struct_exists() {
        // Verify the CSVMint type exists and has the expected address type
        let _addr: Address = Address::ZERO;
        let _bytes: Bytes = Bytes::default();
        let _fixed: FixedBytes<32> = FixedBytes::<32>::ZERO;
    }
}
