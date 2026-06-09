// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CSVSeal — Cross-Chain Sanad Transfer on Ethereum
/// @notice Unified contract for lock, mint, and refund operations
/// @dev Canonical naming: all functions use snake_case, matching Solana/Sui/Aptos
contract CSVSeal {
    /// @notice Protocol version
    uint256 public constant VERSION = 4; // Canonical naming version

    uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
    uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
    uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
    uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
    uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

    /// @notice Chain IDs — canonical across all chains
    uint8 public constant CHAIN_BITCOIN = 0;
    uint8 public constant CHAIN_SUI = 1;
    uint8 public constant CHAIN_APTOS = 2;
    uint8 public constant CHAIN_ETHEREUM = 3;
    uint8 public constant CHAIN_SOLANA = 4;

    // ==================== Canonical State Enum ====================

    /// @notice Sanad lifecycle state — canonical values across all chains
    /// @dev 0=Uncreated, 1=Created, 2=Active, 3=Locked, 4=Consumed, 5=Minted, 6=Transferred, 7=Refunded, 8=Burned, 9=Invalid
    enum SanadState {
        Uncreated,
        Created,
        Active,
        Locked,
        Consumed,
        Minted,
        Transferred,
        Refunded,
        Burned,
        Invalid
    }

    /// @notice Seal lifecycle state — canonical values across all chains
    /// @dev 0=Created, 1=Consumed, 2=Locked, 3=Minted, 4=Refunded
    enum SealState {
        Created,
        Consumed,
        Locked,
        Minted,
        Refunded
    }

    // ==================== Canonical View Structures ====================

    /// @notice Full state view for a Sanad — returned by get_sanad_state()
    struct SanadStateView {
        bytes32 sanadId;
        bytes32 sealId;
        bytes32 commitment;
        address owner;
        uint8 sourceChain;
        uint8 currentChain;
        uint8 destinationChain;
        SanadState state;
        bytes32 nullifier;
        uint256 createdAt;
        uint256 updatedAt;
        uint256 lockedAt;
        uint256 consumedAt;
        uint256 mintedAt;
        uint256 refundedAt;
        bytes32 lastTx;
    }

    /// @notice Full state view for a Seal — returned by get_seal_state()
    struct SealStateView {
        bytes32 sealId;
        bytes32 sanadId;
        bytes32 commitment;
        SealState state;
        uint256 consumedAt;
        uint256 lockedAt;
    }

    // ==================== Storage ====================

    address public owner;
    address public immutable verifier;
    bytes32 public trustedProofRoot;
    uint256 public proofRootBlockHeight;

    mapping(bytes32 => bool) public usedSeals;
    mapping(bytes32 => bool) public mintedSanads;
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => uint256) public commitmentAnchorHeight;

    struct SanadMetadata {
        uint8 assetClass;
        bytes32 assetId;
        bytes32 metadataHash;
        uint8 proofSystem;
        bytes32 proofRoot;
    }
    mapping(bytes32 => SanadMetadata) public sanadMetadata;

    struct LockRecord {
        bytes32 commitment;
        address owner;
        uint256 timestamp;
        uint8 destinationChain;
        bytes32 destinationOwnerRoot;
        SanadMetadata metadata;
        bool refunded;
    }
    mapping(bytes32 => LockRecord) public locks;

    /// @notice Canonical Sanad state tracking
    mapping(bytes32 => SanadState) public sanadStates;
    mapping(bytes32 => bytes32) public sanadSealId; // sanad_id -> seal_id
    mapping(bytes32 => uint256) public sanadCreatedAt;
    mapping(bytes32 => uint256) public sanadLockedAt;
    mapping(bytes32 => uint256) public sanadConsumedAt;
    mapping(bytes32 => uint256) public sanadMintedAt;
    mapping(bytes32 => uint256) public sanadRefundedAt;
    mapping(bytes32 => bytes32) public sanadLastTx;

    uint256 public constant REFUND_TIMEOUT = 24 hours;

    // ==================== Canonical Events ====================

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when a seal is created
    event SanadCreated(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint256 timestamp);

    /// @notice Emitted when a seal is consumed (canonical name, replaces SealUsed)
    event SanadConsumed(bytes32 indexed sanadId, bytes32 indexed nullifier, address indexed consumer, uint256 timestamp);

    /// @notice Emitted when a Sanad is locked for cross-chain transfer (canonical name, replaces CrossChainLock)
    event SanadLocked(
        bytes32 indexed sanadId,
        bytes32 indexed commitment,
        address indexed owner,
        uint8 destinationChain,
        bytes destinationOwner,
        uint256 timestamp
    );

    /// @notice Emitted when a Sanad is minted on destination (canonical name, replaces SanadMinted)
    event SanadMinted(
        bytes32 indexed sanadId,
        bytes32 indexed commitment,
        address indexed owner,
        uint8 sourceChain,
        bytes sourceSealRef,
        uint256 timestamp
    );

    /// @notice Emitted when a locked Sanad is refunded (canonical name)
    event SanadRefunded(
        bytes32 indexed sanadId,
        bytes32 indexed commitment,
        address indexed claimant,
        string reason,
        uint256 timestamp
    );

    /// @notice Emitted when Sanad ownership is transferred
    event SanadTransferred(bytes32 indexed sanadId, address indexed from, address indexed to, uint256 timestamp);

    /// @notice Emitted when a nullifier is registered
    event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanadId, uint8 sourceChain, uint256 timestamp);

    /// @notice Emitted when a commitment is anchored
    event CommitmentAnchored(bytes32 indexed commitment, bytes32 indexed sealId, address indexed owner, uint256 timestamp);

    /// @notice Emitted when proof root is updated
    event ProofRootUpdated(bytes32 indexed proofRoot, uint256 blockNumber, address indexed updater);

    /// @notice Emitted when replay is detected
    event ReplayDetected(bytes32 indexed replayId, bytes32 indexed sanadId, uint256 timestamp);

    // Legacy events (backward compatibility — emit alongside canonical events during transition)
    event SealUsed(bytes32 indexed sealId, bytes32 commitment);
    event CrossChainLock(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint8 destinationChain, bytes destinationOwner, uint256 timestamp);

    // ==================== Errors ====================

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
    error SanadNotFound();

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // ==================== Constructor ====================

    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = _verifier;
        owner = msg.sender;
        trustedProofRoot = bytes32(0);
        proofRootBlockHeight = block.number;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ==================== Governance ====================

    function transfer_ownership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function update_proof_root(bytes32 _proofRoot) external {
        if (msg.sender != verifier) revert Unauthorized();
        if (_proofRoot == bytes32(0)) revert InvalidProofRoot();

        trustedProofRoot = _proofRoot;
        proofRootBlockHeight = block.number;

        emit ProofRootUpdated(_proofRoot, block.number, msg.sender);
    }

    // ==================== Lifecycle Mutations (Canonical Names) ====================

    /// @notice Create a seal (anchor commitment on-chain)
    function create_seal(bytes32 commitment, bytes32 sealId) external returns (bool) {
        if (commitmentAnchorHeight[commitment] != 0) revert CommitmentNotAnchored();

        commitmentAnchorHeight[commitment] = block.number;
        sanadStates[sealId] = SanadState.Created;
        sanadSealId[sealId] = sealId;
        sanadCreatedAt[sealId] = block.timestamp;
        sanadLastTx[sealId] = bytes32(0);

        emit SanadCreated(sealId, commitment, msg.sender, block.timestamp);
        emit CommitmentAnchored(commitment, sealId, msg.sender, block.timestamp);
        emit SealUsed(sealId, commitment); // Legacy

        return true;
    }

    /// @notice Consume a seal (mark as used, register nullifier)
    function consume_seal(bytes32 sealId, bytes32 nullifier) external {
        if (usedSeals[sealId]) revert SanadAlreadyConsumed();

        usedSeals[sealId] = true;
        if (nullifier != bytes32(0)) {
            nullifiers[nullifier] = true;
        }
        sanadStates[sealId] = SanadState.Consumed;
        sanadConsumedAt[sealId] = block.timestamp;
        sanadLastTx[sealId] = nullifier;

        emit SanadConsumed(sealId, nullifier, msg.sender, block.timestamp);
        emit SealUsed(sealId, bytes32(0)); // Legacy

        if (nullifier != bytes32(0)) {
            emit NullifierRegistered(nullifier, sealId, CHAIN_ETHEREUM, block.timestamp);
        }
    }

    /// @notice Lock a Sanad for cross-chain transfer (canonical name, replaces lockSanad)
    function lock_sanad(
        bytes32 sanadId,
        bytes32 commitment,
        uint8 destinationChain,
        bytes calldata destinationOwner
    ) external {
        _lock_sanad_internal(sanadId, commitment, destinationChain, destinationOwner, SanadMetadata({
            assetClass: ASSET_CLASS_UNSPECIFIED,
            assetId: bytes32(0),
            metadataHash: bytes32(0),
            proofSystem: PROOF_SYSTEM_UNSPECIFIED,
            proofRoot: bytes32(0)
        }));
    }

    /// @notice Lock a Sanad with metadata
    function lock_sanad_with_metadata(
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
        _lock_sanad_internal(sanadId, commitment, destinationChain, destinationOwner, SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem,
            proofRoot: proofRoot
        }));
    }

    function _lock_sanad_internal(
        bytes32 sanadId,
        bytes32 commitment,
        uint8 destinationChain,
        bytes calldata destinationOwner,
        SanadMetadata memory metadata
    ) internal {
        if (usedSeals[sanadId]) revert SanadAlreadyConsumed();

        (uint256 lockTimestamp, bool lockRefunded) = (locks[sanadId].timestamp, locks[sanadId].refunded);
        if (lockTimestamp != 0 && !lockRefunded) revert SanadAlreadyLocked();

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

        sanadStates[sanadId] = SanadState.Locked;
        sanadLockedAt[sanadId] = block.timestamp;
        sanadLastTx[sanadId] = bytes32(0);

        emit SanadLocked(sanadId, commitment, msg.sender, destinationChain, destinationOwner, block.timestamp);
        emit CrossChainLock(sanadId, commitment, msg.sender, destinationChain, destinationOwner, block.timestamp); // Legacy
    }

    /// @notice Mint a Sanad on destination chain (canonical name, replaces mintSanad)
    function mint_sanad(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 stateRoot,
        uint8 sourceChain,
        bytes calldata sourceSealPoint,
        bytes calldata proof,
        bytes32 proofRoot,
        uint256 leafPosition
    ) external returns (bool) {
        return _mint_sanad_internal(sanadId, commitment, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, leafPosition, SanadMetadata({
            assetClass: ASSET_CLASS_UNSPECIFIED,
            assetId: bytes32(0),
            metadataHash: bytes32(0),
            proofSystem: PROOF_SYSTEM_UNSPECIFIED,
            proofRoot: proofRoot
        }));
    }

    /// @notice Mint a Sanad with metadata
    function mint_sanad_with_metadata(
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
        return _mint_sanad_internal(sanadId, commitment, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, leafPosition, SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem,
            proofRoot: proofRoot
        }));
    }

    function _mint_sanad_internal(
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

        if (sourceChain == CHAIN_BITCOIN) {
            _verify_bitcoin_proof(sanadId, commitment, proof, proofRoot, leafPosition);
        } else {
            _verify_cross_chain_proof(sanadId, commitment, sourceChain, proof, proofRoot, leafPosition);
        }

        mintedSanads[sanadId] = true;
        sanadMetadata[sanadId] = metadata;
        sanadStates[sanadId] = SanadState.Minted;
        sanadMintedAt[sanadId] = block.timestamp;
        sanadLastTx[sanadId] = bytes32(0);

        emit SanadMinted(sanadId, commitment, msg.sender, sourceChain, sourceSealPoint, block.timestamp);
    }

    /// @notice Refund a locked Sanad after timeout (canonical name)
    function refund_sanad(bytes32 sanadId, bytes32 destinationOwnerHash) external {
        LockRecord storage lock = locks[sanadId];

        if (lock.timestamp == 0) revert SanadNotFound();
        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) revert TimeoutNotExpired();
        if (lock.destinationOwnerRoot != destinationOwnerHash) revert InvalidProof();
        if (lock.owner != msg.sender) revert NotOwner();
        if (lock.refunded) revert RefundAlreadyClaimed();
        if (mintedSanads[sanadId]) revert SanadAlreadyMinted();

        lock.refunded = true;
        usedSeals[sanadId] = false;

        sanadStates[sanadId] = SanadState.Refunded;
        sanadRefundedAt[sanadId] = block.timestamp;
        sanadLastTx[sanadId] = bytes32(0);

        emit SanadRefunded(sanadId, lock.commitment, msg.sender, "timeout", block.timestamp);
    }

    /// @notice Transfer Sanad ownership (same chain)
    function transfer_sanad(bytes32 sanadId, address newOwner) external {
        if (sanadStates[sanadId] != SanadState.Active && sanadStates[sanadId] != SanadState.Created) revert SanadNotFound();
        if (locks[sanadId].timestamp != 0 && !locks[sanadId].refunded) revert SanadAlreadyLocked();

        address currentOwner = locks[sanadId].owner;
        if (msg.sender != currentOwner && msg.sender != owner) revert NotOwner();

        locks[sanadId].owner = newOwner;
        sanadStates[sanadId] = SanadState.Transferred;
        sanadLastTx[sanadId] = bytes32(0);

        emit SanadTransferred(sanadId, currentOwner, newOwner, block.timestamp);
    }

    /// @notice Register nullifier for replay protection
    function register_nullifier(bytes32 nullifier, bytes32 sanadId, uint8 sourceChain) external {
        if (nullifiers[nullifier]) revert NullifierAlreadyRegistered();

        nullifiers[nullifier] = true;

        emit NullifierRegistered(nullifier, sanadId, sourceChain, block.timestamp);
    }

    /// @notice Anchor commitment on-chain
    function anchor_commitment(bytes32 commitment, bytes32 sealId) external {
        if (commitmentAnchorHeight[commitment] != 0) revert CommitmentNotAnchored();

        commitmentAnchorHeight[commitment] = block.number;

        emit CommitmentAnchored(commitment, sealId, msg.sender, block.timestamp);
    }

    /// @notice Record metadata for a Sanad
    function record_sanad_metadata(
        bytes32 sanadId,
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem,
        bytes32 proofRoot
    ) external {
        if (sanadStates[sanadId] == SanadState.Uncreated || sanadStates[sanadId] == SanadState.Invalid) revert SanadNotFound();

        sanadMetadata[sanadId] = SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem,
            proofRoot: proofRoot
        });
    }

    // ==================== View Functions (Canonical Names) ====================

    /// @notice Get full Sanad state view
    function get_sanad_state(bytes32 sanadId) external view returns (SanadStateView memory) {
        SanadState state = sanadStates[sanadId];
        if (state == SanadState.Uncreated) {
            // Check if it exists in locks
            if (locks[sanadId].timestamp != 0) {
                state = SanadState.Locked;
            } else if (mintedSanads[sanadId]) {
                state = SanadState.Minted;
            } else if (usedSeals[sanadId]) {
                state = SanadState.Consumed;
            }
        }

        LockRecord storage lock = locks[sanadId];

        return SanadStateView({
            sanadId: sanadId,
            sealId: sanadSealId[sanadId],
            commitment: lock.commitment,
            owner: lock.owner,
            sourceChain: 0,
            currentChain: CHAIN_ETHEREUM,
            destinationChain: lock.destinationChain,
            state: state,
            nullifier: bytes32(0),
            createdAt: sanadCreatedAt[sanadId],
            updatedAt: block.timestamp,
            lockedAt: sanadLockedAt[sanadId],
            consumedAt: sanadConsumedAt[sanadId],
            mintedAt: sanadMintedAt[sanadId],
            refundedAt: sanadRefundedAt[sanadId],
            lastTx: sanadLastTx[sanadId]
        });
    }

    /// @notice Get full Seal state view
    function get_seal_state(bytes32 sealId) external view returns (SealStateView memory) {
        SealState state;
        if (usedSeals[sealId]) {
            state = SealState.Consumed;
        } else if (locks[sealId].timestamp != 0 && !locks[sealId].refunded) {
            state = SealState.Locked;
        } else {
            state = SealState.Created;
        }

        return SealStateView({
            sealId: sealId,
            sanadId: sealId,
            commitment: locks[sealId].commitment,
            state: state,
            consumedAt: sanadConsumedAt[sealId],
            lockedAt: sanadLockedAt[sealId]
        });
    }

    /// @notice Check if seal is available (not consumed)
    function is_seal_available(bytes32 sealId) external view returns (bool) {
        return !usedSeals[sealId];
    }

    /// @notice Check if seal is consumed (canonical name, replaces isSealUsed)
    function is_seal_consumed(bytes32 sealId) external view returns (bool) {
        return usedSeals[sealId];
    }

    /// @notice Check if nullifier is registered
    function is_nullifier_registered(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Check if commitment is anchored
    function is_commitment_anchored(bytes32 commitment) external view returns (bool) {
        return commitmentAnchorHeight[commitment] != 0;
    }

    /// @notice Check if Sanad is minted
    function is_sanad_minted(bytes32 sanadId) external view returns (bool) {
        return mintedSanads[sanadId];
    }

    /// @notice Check if refund is available
    function can_refund(bytes32 sanadId) external view returns (bool) {
        LockRecord storage lock = locks[sanadId];
        if (lock.timestamp == 0) return false;
        if (lock.refunded) return false;
        if (block.timestamp < lock.timestamp + REFUND_TIMEOUT) return false;
        return true;
    }

    /// @notice Get lock details (legacy compatibility)
    function get_lock_info(bytes32 sanadId) external view returns (
        bytes32 commitment,
        uint256 timestamp,
        uint8 destinationChain,
        bool refunded
    ) {
        LockRecord storage lock = locks[sanadId];
        return (lock.commitment, lock.timestamp, lock.destinationChain, lock.refunded);
    }

    /// @notice Get Sanad metadata
    function get_sanad_metadata(bytes32 sanadId) external view returns (
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem,
        bytes32 proofRoot
    ) {
        SanadMetadata storage metadata = sanadMetadata[sanadId];
        return (metadata.assetClass, metadata.assetId, metadata.metadataHash, metadata.proofSystem, metadata.proofRoot);
    }

    // ==================== Proof Verification (Internal) ====================

    function _verify_cross_chain_proof(
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

        if (sourceChain == CHAIN_ETHEREUM || sourceChain == CHAIN_SOLANA) {
            leaf = keccak256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verify_merkle_proof_keccak256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else if (sourceChain == CHAIN_SUI) {
            leaf = blake2b256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verify_merkle_proof_blake2b256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else if (sourceChain == CHAIN_APTOS) {
            leaf = sha3_256(abi.encodePacked(sanadId, commitment, sourceChain));
            if (!_verify_merkle_proof_sha3_256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
        } else {
            revert InvalidProof();
        }
    }

    function _verify_bitcoin_proof(
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

        bytes32 leaf = double_sha256(abi.encodePacked(sanadId, commitment));
        if (!_verify_merkle_proof_double_sha256(proof, proofRoot, leaf, leafPosition)) revert InvalidProof();
    }

    function _verify_merkle_proof_keccak256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafPosition) internal pure returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafPosition >> i) & 1 == 0) {
                current = _hash_pair_keccak256(current, sibling);
            } else {
                current = _hash_pair_keccak256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_double_sha256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafPosition) internal pure returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafPosition >> i) & 1 == 0) {
                current = _hash_pair_double_sha256(current, sibling);
            } else {
                current = _hash_pair_double_sha256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_blake2b256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafPosition) internal view returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafPosition >> i) & 1 == 0) {
                current = _hash_pair_blake2b256(current, sibling);
            } else {
                current = _hash_pair_blake2b256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_sha3_256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafPosition) internal view returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafPosition >> i) & 1 == 0) {
                current = _hash_pair_sha3_256(current, sibling);
            } else {
                current = _hash_pair_sha3_256(sibling, current);
            }
        }
        return current == root;
    }

    function _hash_pair_keccak256(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    function _hash_pair_double_sha256(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return double_sha256(abi.encodePacked(a, b));
    }

    function _hash_pair_blake2b256(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return blake2b256(abi.encodePacked(a, b));
    }

    function _hash_pair_sha3_256(bytes32 a, bytes32 b) internal view returns (bytes32) {
        return sha3_256(abi.encodePacked(a, b));
    }

    function double_sha256(bytes memory data) internal pure returns (bytes32) {
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

    // ==================== Batch Operations ====================

    function batch_mint_sanads(
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
        if (sanadIds.length != commitments.length || sanadIds.length != stateRoots.length || sanadIds.length != proofs.length || sanadIds.length != leafPositions.length) revert ArraysMismatch();

        for (uint256 i = 0; i < sanadIds.length; i++) {
            mint_sanad(sanadIds[i], commitments[i], stateRoots[i], sourceChain, sourceSealPoint, proofs[i], proofRoot, leafPositions[i]);
        }
    }
}
