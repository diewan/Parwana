// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CSVSeal — Cross-Chain Sanad Transfer on Ethereum
/// @notice Unified contract for lock, mint, and refund operations on Ethereum
/// @dev Merges CSVLock and CSVMint functionality into a single contract
contract CSVSeal {
    /// @notice Protocol version — incremented on every breaking change
    uint256 public constant VERSION = 3; // Merged version

    uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
    uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
    uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
    uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
    uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

    /// @notice Chain IDs for cross-chain transfers
    uint8 public constant CHAIN_BITCOIN = 0;
    uint8 public constant CHAIN_SUI = 1;
    uint8 public constant CHAIN_APTOS = 2;
    uint8 public constant CHAIN_ETHEREUM = 3;
    uint8 public constant CHAIN_SOLANA = 4;

    /// @notice Contract owner - can call owner-only functions
    address public owner;

    /// @notice Trusted verifier address that validates proofs before minting
    address public immutable verifier;

    /// @notice Trusted proof root (Merkle root for cross-chain proofs)
    bytes32 public trustedProofRoot;

    /// @notice Block height of last proof root update
    uint256 public proofRootBlockHeight;

    /// @notice Tracks consumed nullifiers (seal single-use)
    mapping(bytes32 => bool) public usedSeals;

    /// @notice Tracks minted Sanads (prevents double-mint)
    mapping(bytes32 => bool) public mintedSanads;

    /// @notice Tracks registered nullifiers (prevents double-spend on Ethereum)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Anchored commitments (commitment -> block height)
    mapping(bytes32 => uint256) public commitmentAnchorHeight;

    /// @notice Cross-chain metadata shared by all CSV contracts.
    struct SanadMetadata {
        uint8 assetClass;
        bytes32 assetId;
        bytes32 metadataHash;
        uint8 proofSystem;
        bytes32 proofRoot;
    }

    mapping(bytes32 => SanadMetadata) public sanadMetadata;

    /// @notice Lock record for refund support
    struct LockRecord {
        bytes32 commitment;
        address owner;
        uint256 timestamp;
        uint8 destinationChain;
        bytes32 destinationOwnerRoot;
        SanadMetadata metadata;
        bool refunded;
    }

    /// @notice Tracks lock events for refund verification
    mapping(bytes32 => LockRecord) public locks;

    /// @notice Refund timeout — 24 hours after lock
    uint256 public constant REFUND_TIMEOUT = 24 hours;

    /// @notice Emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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

    /// @notice Emitted when a Sanad is minted from cross-chain transfer
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

    /// @notice Emitted when a nullifier is registered
    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed sanadId,
        uint8 sourceChain,
        bytes sourceSealRef,
        uint256 blockNumber
    );

    /// @notice Emitted when a commitment is anchored
    event CommitmentAnchored(
        bytes32 indexed commitment,
        bytes32 indexed sealId,
        address indexed owner,
        uint256 blockNumber
    );

    /// @notice Emitted when proof root is updated
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

    /// @notice Constructor to set verifier and initialize owner
    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = _verifier;
        owner = msg.sender;
        trustedProofRoot = bytes32(0);
        proofRootBlockHeight = block.number;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Transfer ownership of the contract to a new address
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Update the trusted proof root (verifier only)
    function updateProofRoot(bytes32 _proofRoot) external {
        if (msg.sender != verifier) revert Unauthorized();
        if (_proofRoot == bytes32(0)) revert InvalidProofRoot();
        
        trustedProofRoot = _proofRoot;
        proofRootBlockHeight = block.number;
        
        emit ProofRootUpdated(_proofRoot, block.number, msg.sender);
    }

    // ==================== Lock Operations ====================

    /// @notice Lock a Sanad for cross-chain transfer
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

    /// @notice Lock a Sanad with asset/proof metadata
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
        bool isConsumed = usedSeals[sanadId];
        (uint256 lockTimestamp, bool lockRefunded) = (locks[sanadId].timestamp, locks[sanadId].refunded);
        
        if (isConsumed) {
            revert SanadAlreadyConsumed();
        }
        if (lockTimestamp != 0 && !lockRefunded) {
            revert SanadAlreadyLocked();
        }

        bytes32 destinationOwnerRoot = keccak256(destinationOwner);

        usedSeals[sanadId] = true;
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
            bytes32(0),
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
        emit SealUsed(sanadId, commitment);
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
    function markSealUsed(bytes32 sealId, bytes32 commitment) external onlyOwner {
        if (usedSeals[sealId]) {
            revert SanadAlreadyConsumed();
        }
        usedSeals[sealId] = true;
        emit SealUsed(sealId, commitment);
    }

    /// @notice Claim a refund for a locked Sanad that was never minted
    function refundSanad(bytes32 sanadId, bytes32 destinationOwnerHash) external {
        LockRecord storage lock = locks[sanadId];

        if (lock.timestamp == 0) {
            revert SanadAlreadyConsumed();
        }

        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) {
            revert TimeoutNotExpired();
        }

        if (lock.destinationOwnerRoot != destinationOwnerHash) {
            revert InvalidProof();
        }
        if (lock.owner != msg.sender) {
            revert NotOwner();
        }

        if (lock.refunded) {
            revert RefundAlreadyClaimed();
        }

        // Check if sanad was minted locally (no cross-contract call needed)
        if (mintedSanads[sanadId]) {
            revert SanadAlreadyMinted();
        }

        lock.refunded = true;
        usedSeals[sanadId] = false;

        emit SanadRefunded(sanadId, lock.commitment, msg.sender, block.timestamp);
    }

    // ==================== Mint Operations ====================

    /// @notice Register a nullifier for a Sanad (prevents double-spend)
    function registerNullifier(
        bytes32 nullifier,
        bytes32 sanadId,
        uint8 sourceChain,
        bytes calldata sourceSealRef
    ) external {
        if (nullifiers[nullifier]) revert NullifierAlreadyRegistered();
        
        nullifiers[nullifier] = true;
        
        emit NullifierRegistered(nullifier, sanadId, sourceChain, sourceSealRef, block.number);
    }

    /// @notice Anchor a commitment on-chain
    function anchorCommitment(bytes32 commitment, bytes32 sealId) external {
        if (commitmentAnchorHeight[commitment] != 0) revert CommitmentNotAnchored();
        
        commitmentAnchorHeight[commitment] = block.number;
        
        emit CommitmentAnchored(commitment, sealId, msg.sender, block.number);
    }

    /// @notice Mint a new Sanad from a verified cross-chain transfer
    function mintSanad(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 stateRoot,
        uint8 sourceChain,
        bytes calldata sourceSealPoint,
        bytes calldata proof,
        bytes32 proofRoot,
        uint256 leafPosition
    ) external returns (bool) {
        return _mintSanad(
            sanadId,
            commitment,
            stateRoot,
            sourceChain,
            sourceSealPoint,
            proof,
            proofRoot,
            leafPosition,
            SanadMetadata({
                assetClass: ASSET_CLASS_UNSPECIFIED,
                assetId: bytes32(0),
                metadataHash: bytes32(0),
                proofSystem: PROOF_SYSTEM_UNSPECIFIED,
                proofRoot: proofRoot
            })
        );
    }

    /// @notice Mint a Sanad with token/NFT/proof metadata
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
    ) external returns (bool) {
        SanadMetadata memory metadata = SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem,
            proofRoot: proofRoot
        });
        _validateMetadata(metadata);
        return _mintSanad(sanadId, commitment, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, leafPosition, metadata);
    }

    function _mintSanad(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 stateRoot,
        uint8 sourceChain,
        bytes calldata sourceSealPoint,
        bytes calldata proof,
        bytes32 proofRoot,
        uint256 leafPosition,
        SanadMetadata memory metadata
    ) internal returns (bool) {
        if (proofRoot != trustedProofRoot) revert InvalidProofRoot();
        
        if (mintedSanads[sanadId]) revert SanadAlreadyMinted();
        if (stateRoot == bytes32(0)) revert InvalidProof();

        if (sourceChain == 0) { // CHAIN_BITCOIN
            _verifyBitcoinProof(sanadId, commitment, proof, proofRoot, leafPosition);
        } else {
            _verifyCrossChainProof(sanadId, commitment, sourceChain, proof, proofRoot, leafPosition);
        }

        mintedSanads[sanadId] = true;
        sanadMetadata[sanadId] = metadata;

        emit SanadMinted(
            sanadId,
            commitment,
            msg.sender,
            sourceChain,
            sourceSealPoint,
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot,
            block.number
        );
        emit SanadMetadataRecorded(
            sanadId,
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot
        );

        return true;
    }

    // ==================== Proof Verification ====================

    function _verifyCrossChainProof(
        bytes32 sanadId,
        bytes32 commitment,
        uint8 sourceChain,
        bytes calldata proof,
        bytes32 proofRoot,
        uint256 leafPosition
    ) internal view {
        if (proof.length == 0) revert InvalidProof();
        if (proofRoot == bytes32(0)) revert InvalidProof();
        if (sanadId == bytes32(0)) revert InvalidProof();
        if (commitment == bytes32(0)) revert InvalidProof();

        bytes32 leaf;
        
        if (sourceChain == 3 || sourceChain == 4) { // Ethereum (3) or Solana (4)
            leaf = keccak256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verifyMerkleProofKeccak256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else if (sourceChain == 1) { // Sui (1)
            leaf = blake2b256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verifyMerkleProofBlake2b256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else if (sourceChain == 2) { // Aptos (2)
            leaf = sha3_256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verifyMerkleProofSha3_256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else {
            revert InvalidProof();
        }
    }

    function _verifyBitcoinProof(
        bytes32 sanadId,
        bytes32 commitment,
        bytes calldata proof,
        bytes32 proofRoot,
        uint256 leafPosition
    ) internal pure {
        if (proof.length == 0) revert InvalidProof();
        if (proofRoot == bytes32(0)) revert InvalidProof();
        if (sanadId == bytes32(0)) revert InvalidProof();
        if (commitment == bytes32(0)) revert InvalidProof();

        bytes32 leaf = doubleSha256(abi.encodePacked(sanadId, commitment));

        if (!_verifyMerkleProofDoubleSha256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
    }

    function _verifyMerkleProofKeccak256(
        bytes calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 leafPosition
    ) internal pure returns (bool) {
        if (proof.length == 0) return false;
        if (proof.length % 32 != 0) return false;

        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;

        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly {
                sibling := calldataload(add(proof.offset, mul(i, 32)))
            }

            if ((leafPosition >> i) & 1 == 0) {
                current = _hashPairKeccak256(current, sibling);
            } else {
                current = _hashPairKeccak256(sibling, current);
            }
        }

        return current == root;
    }

    function _verifyMerkleProofDoubleSha256(
        bytes calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 leafPosition
    ) internal pure returns (bool) {
        if (proof.length == 0) return false;
        if (proof.length % 32 != 0) return false;

        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;

        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly {
                sibling := calldataload(add(proof.offset, mul(i, 32)))
            }

            if ((leafPosition >> i) & 1 == 0) {
                current = _hashPairDoubleSha256(current, sibling);
            } else {
                current = _hashPairDoubleSha256(sibling, current);
            }
        }

        return current == root;
    }

    function _verifyMerkleProofBlake2b256(
        bytes calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 leafPosition
    ) internal view returns (bool) {
        if (proof.length == 0) return false;
        if (proof.length % 32 != 0) return false;

        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;

        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly {
                sibling := calldataload(add(proof.offset, mul(i, 32)))
            }

            if ((leafPosition >> i) & 1 == 0) {
                current = _hashPairBlake2b256(current, sibling);
            } else {
                current = _hashPairBlake2b256(sibling, current);
            }
        }

        return current == root;
    }

    function _verifyMerkleProofSha3_256(
        bytes calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 leafPosition
    ) internal view returns (bool) {
        if (proof.length == 0) return false;
        if (proof.length % 32 != 0) return false;

        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;

        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly {
                sibling := calldataload(add(proof.offset, mul(i, 32)))
            }

            if ((leafPosition >> i) & 1 == 0) {
                current = _hashPairSha3_256(current, sibling);
            } else {
                current = _hashPairSha3_256(sibling, current);
            }
        }

        return current == root;
    }

    function _hashPairKeccak256(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    function _hashPairDoubleSha256(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return doubleSha256(abi.encodePacked(a, b));
    }

    function _hashPairBlake2b256(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return blake2b256(abi.encodePacked(a, b));
    }

    function _hashPairSha3_256(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return sha3_256(abi.encodePacked(a, b));
    }

    function doubleSha256(bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    function blake2b256(bytes memory data) internal view returns (bytes32) {
        (bool success, bytes memory result) = address(0x09).staticcall(data);
        require(success, "BLAKE2b256 precompile failed");
        return bytes32(result);
    }

    function sha3_256(bytes memory data) internal view returns (bytes32) {
        (bool success, bytes memory result) = address(0x05).staticcall(data);
        require(success, "SHA3-256 precompile failed");
        return bytes32(result);
    }

    // ==================== View Functions ====================

    /// @notice Check if a seal/Sanad has been consumed
    function isSealUsed(bytes32 sealId) external view returns (bool) {
        return usedSeals[sealId];
    }

    /// @notice Check if a Sanad has been minted on this chain
    function isSanadMinted(bytes32 sanadId) external view returns (bool) {
        return mintedSanads[sanadId];
    }

    /// @notice Check if a nullifier has been registered
    function isNullifierRegistered(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Check if a commitment is anchored
    function isCommitmentAnchored(bytes32 commitment) external view returns (bool) {
        return commitmentAnchorHeight[commitment] != 0;
    }

    /// @notice Get lock details for a Sanad
    function getLockInfo(bytes32 sanadId) external view returns (
        bytes32 commitment,
        uint256 timestamp,
        uint8 destinationChain,
        bool refunded
    ) {
        LockRecord storage lock = locks[sanadId];
        return (lock.commitment, lock.timestamp, lock.destinationChain, lock.refunded);
    }

    /// @notice Get metadata attached to a locked Sanad
    function getSanadMetadata(bytes32 sanadId) external view returns (
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem,
        bytes32 proofRoot
    ) {
        SanadMetadata storage metadata = sanadMetadata[sanadId];
        return (
            metadata.assetClass,
            metadata.assetId,
            metadata.metadataHash,
            metadata.proofSystem,
            metadata.proofRoot
        );
    }

    /// @notice Check if a refund can be claimed for a Sanad
    function canRefund(bytes32 sanadId) external view returns (bool) {
        LockRecord storage lock = locks[sanadId];

        if (lock.timestamp == 0) return false;
        if (lock.refunded) return false;
        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) return false;

        return true;
    }

    // ==================== Batch Operations ====================

    /// @notice Batch mint multiple Sanads (for efficiency)
    function batchMintSanads(
        bytes32[] calldata sanadIds,
        bytes32[] calldata commitments,
        bytes32[] calldata stateRoots,
        uint8 sourceChain,
        bytes calldata sourceSealPoint,
        bytes[] calldata proofs,
        bytes32 proofRoot,
        uint256[] calldata leafPositions
    ) external {
        if (msg.sender != verifier) revert Unauthorized();

        if (
            sanadIds.length != commitments.length ||
            sanadIds.length != stateRoots.length ||
            sanadIds.length != proofs.length ||
            sanadIds.length != leafPositions.length
        ) revert ArraysMismatch();

        for (uint256 i = 0; i < sanadIds.length; i++) {
            this.mintSanad(
                sanadIds[i],
                commitments[i],
                stateRoots[i],
                sourceChain,
                sourceSealPoint,
                proofs[i],
                proofRoot,
                leafPositions[i]
            );
        }
    }

    // ==================== Modifiers ====================

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
}
