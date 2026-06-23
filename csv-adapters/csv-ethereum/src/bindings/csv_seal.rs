//! CSV Seal Contract Bindings
//!
//! Type-safe bindings for the CSV Seal contract using Alloy.
//! Generated from CSVSeal.sol (merged lock + mint contract)

#![allow(clippy::too_many_arguments)]

use alloy_sol_types::sol;

// Solidity contract ABI
sol! {
    #[sol(rpc)]
    contract CSVSeal {
        uint256 public constant VERSION = 3;

        uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
        uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
        uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
        uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
        uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

        uint8 public constant CHAIN_BITCOIN = 0;
        uint8 public constant CHAIN_SUI = 1;
        uint8 public constant CHAIN_APTOS = 2;
        uint8 public constant CHAIN_ETHEREUM = 3;
        uint8 public constant CHAIN_SOLANA = 4;

        address public owner;
        address public immutable verifier;
        bytes32 public trustedProofRoot;
        uint256 public proofRootBlockHeight;

        struct SanadMetadata {
            uint8 assetClass;
            bytes32 assetId;
            bytes32 metadataHash;
            uint8 proofSystem;
            bytes32 proofRoot;
        }

        struct LockRecord {
            bytes32 commitment;
            address owner;
            uint256 timestamp;
            uint8 destinationChain;
            bytes32 destinationOwnerRoot;
            SanadMetadata metadata;
            bool refunded;
        }

        uint256 public constant REFUND_TIMEOUT = 24 hours;

        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
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
        event SanadMinted(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed owner,
            uint8 sourceChain,
            bytes sourceSealRef,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 proofRoot,
            uint256 blockNumber
        );
        event NullifierRegistered(
            bytes32 indexed nullifier,
            bytes32 indexed sanadId,
            uint8 sourceChain,
            bytes sourceSealRef,
            uint256 blockNumber
        );
        event CommitmentAnchored(
            bytes32 indexed commitment,
            bytes32 indexed sealId,
            address indexed owner,
            uint256 blockNumber
        );
        event ProofRootUpdated(
            bytes32 indexed proofRoot,
            uint256 blockNumber,
            address indexed updater
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
        error InvalidSanadMetadata();
        error NotOwner();
        error ZeroAddress();
        error InvalidProof();
        error NullifierAlreadyRegistered();
        error ArraysMismatch();
        error Unauthorized();
        error InvalidProofRoot();
        error CommitmentNotAnchored();

        constructor(address _verifier);

        function transferOwnership(address newOwner) external;

        function updateProofRoot(bytes32 _proofRoot) external;

        // Lock operations
        function lock_sanad(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 destinationChain,
            bytes calldata destinationOwner
        ) external;

        function lock_sanad_with_metadata(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 destinationChain,
            bytes calldata destinationOwner,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem,
            bytes32 proofRoot
        ) external;

        function markSealUsed(bytes32 sealId, bytes32 commitment) external;

        function refundSanad(bytes32 sanadId, bytes32 destinationOwnerHash) external;

        // Mint operations
        function registerNullifier(
            bytes32 nullifier,
            bytes32 sanadId,
            uint8 sourceChain,
            bytes calldata sourceSealRef
        ) external;

        function anchorCommitment(bytes32 commitment, bytes32 sealId) external;

        function mintSanad(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 stateRoot,
            uint8 sourceChain,
            bytes calldata sourceSealPoint,
            bytes calldata proof,
            bytes32 proofRoot,
            uint256 leafPosition
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
            uint256 leafPosition
        ) external returns (bool);

        // View functions
        function isSealUsed(bytes32 sealId) external view returns (bool);
        function isSanadMinted(bytes32 sanadId) external view returns (bool);
        function isNullifierRegistered(bytes32 nullifier) external view returns (bool);
        function isCommitmentAnchored(bytes32 commitment) external view returns (bool);
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

        // Batch operations
        function batchMintSanads(
            bytes32[] calldata sanadIds,
            bytes32[] calldata commitments,
            bytes32[] calldata stateRoots,
            uint8 sourceChain,
            bytes calldata sourceSealPoint,
            bytes[] calldata proofs,
            bytes32 proofRoot,
            uint256[] calldata leafPositions
        ) external;
    }
}

// Re-export the generated types
pub use CSVSeal::*;
