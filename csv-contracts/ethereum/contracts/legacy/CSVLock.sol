// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CSVLock — Cross-Chain Sanad Lock on Ethereum
/// @notice Registers nullifiers, emits lock events, and supports time-locked refunds
contract CSVLock {
    /// @notice Protocol version — incremented on every breaking change
    uint256 public constant VERSION = 1;

    uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
    uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
    uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
    uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
    uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

    /// @notice Contract owner - can call owner-only functions
    address public owner;

    /// @notice Tracks consumed nullifiers (seal single-use)
    mapping(bytes32 => bool) public usedSeals;

    /// @notice Cross-chain metadata shared by all CSV contracts.
    struct SanadMetadata {
        uint8 assetClass;
        bytes32 assetId;
        bytes32 metadataHash;
        uint8 proofSystem;
        bytes32 proofRoot;
    }

    /// @notice Lock record for refund support
    struct LockRecord {
        bytes32 commitment;
        address owner;
        uint256 timestamp;
        uint8 destinationChain;
        bytes32 destinationOwnerRoot; // Hash of destination owner for verification
        SanadMetadata metadata;
        bool refunded;
    }

    /// @notice Tracks lock events for refund verification
    mapping(bytes32 => LockRecord) public locks;

    /// @notice Refund timeout — 24 hours after lock
    uint256 public constant REFUND_TIMEOUT = 24 hours;

    /// @notice Address of the CSVMint contract (to verify no mint happened)
    /// @dev Immutable - set at deployment and cannot be changed
    address public immutable mintContract;

    /// @notice Emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Modifier to restrict function access to only the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    /// @notice Emitted when a Sanad is locked for cross-chain transfer
    event CrossChainLock(
        bytes32 indexed sanadId,
        bytes32 indexed commitment,
        address indexed owner,
        uint8 destinationChain,
        bytes destinationOwner,
        bytes32 sourceTxHash,
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem,
        bytes32 proofRoot
    );

    /// @notice Emitted when a Sanad is consumed (nullifier registered)
    event SealUsed(bytes32 indexed sealId, bytes32 commitment);

    /// @notice Emitted when a locked Sanad is refunded
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
    error NotOwner();
    error ZeroAddress();
    error InvalidProof();


    /// @notice Constructor to set immutable mint contract address and initialize owner
    /// @param _mintContract Address of the CSVMint contract
    constructor(address _mintContract) {
        require(_mintContract != address(0), "Invalid mint contract address");
        mintContract = _mintContract;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Transfer ownership of the contract to a new address
    /// @param newOwner The address to transfer ownership to
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Lock a Sanad for cross-chain transfer
    /// @param sanadId Unique Sanad identifier
    /// @param commitment Sanad's commitment hash
    /// @param destinationChain Target chain ID
    /// @param destinationOwner Encoded destination owner address
    function lockSanad(
        bytes32 sanadId,
        bytes32 commitment,
        uint8 destinationChain,
        bytes calldata destinationOwner
    ) external {
        _lockSanad(
            sanadId,
            commitment,
            destinationChain,
            destinationOwner,
            SanadMetadata({
                assetClass: ASSET_CLASS_UNSPECIFIED,
                assetId: bytes32(0),
                metadataHash: bytes32(0),
                proofSystem: PROOF_SYSTEM_UNSPECIFIED,
                proofRoot: bytes32(0)
            })
        );
    }

    /// @notice Lock a Sanad with asset/proof metadata for token, NFT, or advanced proof flows.
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
    ) external {
        SanadMetadata memory metadata = SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem,
            proofRoot: proofRoot
        });
        _validateMetadata(metadata);
        _lockSanad(sanadId, commitment, destinationChain, destinationOwner, metadata);
    }

    function _lockSanad(
        bytes32 sanadId,
        bytes32 commitment,
        uint8 destinationChain,
        bytes calldata destinationOwner,
        SanadMetadata memory metadata
    ) internal {
        // Gas optimization: combine checks to reduce SLOADs
        (uint256 lockTimestamp, bool lockRefunded) = (locks[sanadId].timestamp, locks[sanadId].refunded);

        if (lockTimestamp != 0 && !lockRefunded) {
            revert SanadAlreadyLocked();
        }

        // Gas optimization: compute hash once before storage writes
        bytes32 destinationOwnerRoot = keccak256(destinationOwner);

        // Batch storage writes
        locks[sanadId] = LockRecord({
            commitment: commitment,
            owner: msg.sender,
            timestamp: block.timestamp,
            destinationChain: destinationChain,
            destinationOwnerRoot: destinationOwnerRoot,
            metadata: metadata,
            refunded: false
        });

        emit CrossChainLock(
            sanadId,
            commitment,
            msg.sender,
            destinationChain,
            destinationOwner,
            bytes32(0), // blockhash(block.number - 1) removed: unreliable beyond 256 blocks
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot
        );

        emit SanadMetadataRecorded(
            sanadId,
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot
        );
    }

    function _validateMetadata(SanadMetadata memory metadata) internal pure {
        if (metadata.assetClass > ASSET_CLASS_PROOF_SANAD) revert InvalidSanadMetadata();
        if (metadata.assetClass != ASSET_CLASS_UNSPECIFIED && metadata.assetId == bytes32(0)) {
            revert InvalidSanadMetadata();
        }
        if (metadata.proofSystem != PROOF_SYSTEM_UNSPECIFIED && metadata.proofRoot == bytes32(0)) {
            revert InvalidSanadMetadata();
        }
    }

    /// @notice Register a nullifier (consume seal without cross-chain transfer)
    /// @dev Only owner can call this function to prevent unauthorized seal consumption
    /// @param sealId Seal identifier
    /// @param commitment Commitment hash
    function markSealUsed(bytes32 sealId, bytes32 commitment) external onlyOwner {
        if (usedSeals[sealId]) {
            revert SanadAlreadyConsumed();
        }
        usedSeals[sealId] = true;
        emit SealUsed(sealId, commitment);
    }

    /// @notice Claim a refund for a locked Sanad that was never minted on destination.
    /// @dev This function allows a user to recover a Sanad if:
    ///   1. The lock was recorded in this contract
    ///   2. The REFUND_TIMEOUT has elapsed since the lock
    ///   3. The Sanad was NOT minted on any destination chain
    ///   4. The refund has not already been claimed
    /// @param sanadId The Sanad identifier to refund
    /// @param destinationOwnerHash Hash of the destination owner (for verification)
    function refundSanad(bytes32 sanadId, bytes32 destinationOwnerHash) external {
        LockRecord storage lock = locks[sanadId];

        // Verify lock exists
        if (lock.timestamp == 0) {
            revert SanadAlreadyConsumed();
        }

        // Verify timeout has elapsed
        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) {
            revert TimeoutNotExpired();
        }

        // Verify the caller is the legitimate owner by checking the destination owner hash
        if (lock.destinationOwnerRoot != destinationOwnerHash) {
            revert InvalidMintContract();
        }
        if (lock.owner != msg.sender) {
            revert NotOwner();
        }

        // Verify not already refunded
        if (lock.refunded) {
            revert RefundAlreadyClaimed();
        }

        // Verify the Sanad was NOT minted on destination chain
        // This requires the mint contract to expose isSanadMinted
        if (mintContract == address(0)) {
            revert InvalidMintContract();
        }
        (bool success, bytes memory data) = mintContract.staticcall(
            abi.encodeWithSignature("isSanadMinted(bytes32)", sanadId)
        );
        require(success && data.length >= 32, "Invalid mint contract response");
        bool isMinted = abi.decode(data, (bool));
        if (isMinted) {
            revert SanadAlreadyMinted();
        }

        // Mark as refunded to prevent re-entrancy and double-claim
        lock.refunded = true;

        // Re-allow the seal for future use (re-create the Sanad)
        usedSeals[sanadId] = false;

        emit SanadRefunded(sanadId, lock.commitment, msg.sender, block.timestamp);
    }

    /// @notice Check if a seal/Sanad has been consumed
    /// @param sealId Seal or Sanad identifier
    /// @return True if consumed
    function isSealUsed(bytes32 sealId) external view returns (bool) {
        return usedSeals[sealId];
    }

    /// @notice Get lock details for a Sanad
    /// @param sanadId The Sanad identifier
    /// @return commitment The commitment hash
    /// @return timestamp When the lock was created
    /// @return destinationChain The target chain ID
    /// @return refunded Whether the lock has been refunded
    function getLockInfo(bytes32 sanadId) external view returns (
        bytes32 commitment,
        uint256 timestamp,
        uint8 destinationChain,
        bool refunded
    ) {
        LockRecord storage lock = locks[sanadId];
        return (lock.commitment, lock.timestamp, lock.destinationChain, lock.refunded);
    }

    /// @notice Get metadata attached to a locked Sanad.
    function getSanadMetadata(bytes32 sanadId) external view returns (
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem,
        bytes32 proofRoot
    ) {
        SanadMetadata storage metadata = locks[sanadId].metadata;
        return (
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot
        );
    }

    /// @notice Check if a refund can be claimed for a Sanad
    /// @param sanadId The Sanad identifier
    /// @return True if refund is claimable
    function canRefund(bytes32 sanadId) external view returns (bool) {
        LockRecord storage lock = locks[sanadId];

        // Must exist
        if (lock.timestamp == 0) return false;
        // Must not be refunded
        if (lock.refunded) return false;
        // Timeout must have elapsed
        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) return false;

        return true;
    }

    /// @notice Sanad state enum for clear on-chain status reporting
    enum SanadState { Uncreated, Active, Locked, Consumed, Refunded }

    /// @notice Get the full on-chain state of a Sanad
    /// @param sanadId The Sanad identifier
    /// @return state The current state (Uncreated=0, Active=1, Locked=2, Consumed=3, Refunded=4)
    /// @return isUsed Whether the seal has been consumed (usedSeals mapping)
    /// @return lockTimestamp When the lock was created (0 if never locked)
    /// @return refunded Whether a refund was claimed
    function getSanadState(bytes32 sanadId) external view returns (
        SanadState state,
        bool isUsed,
        uint256 lockTimestamp,
        bool refunded
    ) {
        isUsed = usedSeals[sanadId];
        LockRecord storage lock = locks[sanadId];
        lockTimestamp = lock.timestamp;
        refunded = lock.refunded;

        if (!isUsed && lockTimestamp == 0) {
            state = SanadState.Uncreated;
        } else if (isUsed && lockTimestamp == 0) {
            state = SanadState.Consumed;
        } else if (refunded) {
            state = SanadState.Refunded;
        } else if (lockTimestamp > 0) {
            state = SanadState.Locked;
        } else {
            state = SanadState.Active;
        }
    }
}
