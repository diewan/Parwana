// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CSVSeal — Cross-Chain Sanad Transfer on Ethereum (thin registry)
/// @notice Unified contract for source lock, verifier-attested destination mint, and refund.
/// @dev Canonical naming: all functions use snake_case, matching Solana/Sui/Aptos.
///
/// Authenticity model (RFC-0012 §9 / ABI_CONSTITUTION.md §9): destination mint is a
/// THIN REGISTRY. Cross-chain correctness is decided OFF-CHAIN by the CSV verifier; this
/// contract does not re-adjudicate the proof. It records a mint only when the calldata
/// carries at least `threshold` distinct valid verifier signatures over the frozen §9.2
/// attestation digest, and it enforces on-chain replay protection
/// (`sanadId` / `nullifier` / `lockEventId` uniqueness).
///
/// The former trusted-root gating model (RFC-0012 Model B: a governance-installed,
/// timelock-rotated root as a mint precondition) is REMOVED from the mint path. It bricked
/// mint on a fresh deploy (the root defaulted to zero and could only move via a 7-day
/// timelock) and was superseded by RFC-0012. No installed root, state root, Merkle proof,
/// or leaf index gates the mint hot path.
contract CSVSeal {
    /// @notice Protocol version (thin-registry / verifier-attested mint)
    uint256 public constant VERSION = 6;

    uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
    uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
    uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
    uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
    uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

    /// @notice Chain identity for the contract ABI (RFC-0012 §6): keccak256("csv.chain.<name>").
    /// @dev Distinct from `ProofLeafV1`'s 1-byte chain id, which is unchanged (RFC-0012 §5).
    bytes32 public constant CHAIN_BITCOIN = keccak256(abi.encodePacked("csv.chain.bitcoin"));
    bytes32 public constant CHAIN_SUI = keccak256(abi.encodePacked("csv.chain.sui"));
    bytes32 public constant CHAIN_APTOS = keccak256(abi.encodePacked("csv.chain.aptos"));
    bytes32 public constant CHAIN_ETHEREUM = keccak256(abi.encodePacked("csv.chain.ethereum"));
    bytes32 public constant CHAIN_SOLANA = keccak256(abi.encodePacked("csv.chain.solana"));

    /// @notice Domain tag for the §9.2 mint attestation digest (23 bytes, ASCII, no NUL).
    string internal constant MINT_ATTESTATION_DOMAIN = "csv.mint.attestation.v1";

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
        bytes32 sourceChain;
        bytes32 currentChain;
        bytes32 destinationChain;
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

    /// @notice Authorized verifier set and threshold `M` (RFC-0012 §9.3).
    /// @dev Generalizes the former immutable `verifier` primitive into an M-of-N set.
    ///      Mint requires >= `threshold` distinct valid signatures over the §9.2 digest.
    mapping(address => bool) public isVerifier;
    address[] public verifiers;
    uint256 public threshold;

    // ---- Replay / registry state (on-chain anti-replay domain) ----
    mapping(bytes32 => bool) public usedSeals;
    mapping(bytes32 => bool) public mintedSanads;
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => bool) public usedLockEvents;
    mapping(bytes32 => uint256) public commitmentAnchorHeight;
    mapping(bytes32 => address) public sealOwners; // Track seal ownership

    /// @notice Archival sanad metadata (RFC-0012 §4: metadata is NOT on the mint hot path).
    struct SanadMetadata {
        uint8 assetClass;
        bytes32 assetId;
        bytes32 metadataHash;
        uint8 proofSystem;
    }
    mapping(bytes32 => SanadMetadata) public sanadMetadata;

    struct LockRecord {
        bytes32 commitment;
        address owner;
        uint256 timestamp;
        bytes32 destinationChain;
        bytes32 destinationOwnerRoot;
        SanadMetadata metadata;
        bool refunded;
    }
    mapping(bytes32 => LockRecord) public locks;

    /// @notice Minimal destination-mint record (RFC-0012 §3: persisted for settlement/inspection).
    /// @dev Stores `keccak256(destinationOwner)`; the full bytes travel in the `SanadMinted` event.
    struct MintRecord {
        bytes32 commitment;
        bytes32 sourceChain;
        bytes32 destinationOwnerHash;
        bytes32 lockEventId;
        bytes32 nullifier;
        uint256 mintedAt;
    }
    mapping(bytes32 => MintRecord) public mintRecords;

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

    // ==================== Verifier-set / ownership timelock (OFF the mint path) ====================

    /// @notice Governance timelock period (7 days default). Scopes ONLY verifier-set and
    ///         ownership changes — never a per-mint precondition (RFC-0012 §9.3).
    uint256 public constant TIMELOCK_PERIOD = 7 days;

    address public pendingOwner;
    uint256 public pendingOwnerValidAfter;

    struct PendingVerifierUpdate {
        address verifier;
        bool add; // true = add to set, false = remove from set
        uint256 newThreshold;
        uint256 validAfter;
        bool active;
    }
    PendingVerifierUpdate public pendingVerifierUpdate;

    // ==================== Canonical Events ====================

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when a seal is created
    event SanadCreated(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint256 timestamp);

    /// @notice Emitted when a seal is consumed (canonical name, replaces SealUsed)
    event SanadConsumed(bytes32 indexed sanadId, bytes32 indexed nullifier, address indexed consumer, uint256 timestamp);

    /// @notice Emitted when a Sanad is locked for cross-chain transfer
    event SanadLocked(
        bytes32 indexed sanadId,
        bytes32 indexed commitment,
        address indexed owner,
        bytes32 destinationChain,
        bytes destinationOwner,
        uint256 timestamp
    );

    /// @notice Emitted when a Sanad is minted on the destination (RFC-0012 §3 / ABI §Canonical Event Names).
    /// @dev Indexed topics chosen for settlement lookup: `sanadId`, `lockEventId` (settlement replay key),
    ///      and `nullifier`. The FULL `destinationOwner` bytes are emitted (contract stores only its hash).
    event SanadMinted(
        bytes32 indexed sanadId,
        bytes32 indexed lockEventId,
        bytes32 indexed nullifier,
        bytes32 commitment,
        bytes32 sourceChain,
        bytes destinationOwner,
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
    event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanadId, bytes32 sourceChain, uint256 timestamp);

    /// @notice Emitted when a commitment is anchored
    event CommitmentAnchored(bytes32 indexed commitment, bytes32 indexed sealId, address indexed owner, uint256 timestamp);

    /// @notice Emitted when replay is detected
    event ReplayDetected(bytes32 indexed replayId, bytes32 indexed sanadId, uint256 timestamp);

    /// @notice Emitted when a verifier is added to the set
    event VerifierAdded(address indexed verifier);

    /// @notice Emitted when a verifier is removed from the set
    event VerifierRemoved(address indexed verifier);

    /// @notice Emitted when the signature threshold `M` is updated
    event ThresholdUpdated(uint256 threshold);

    /// @notice Emitted when a verifier-set update is scheduled (timelock)
    event VerifierUpdateScheduled(address indexed verifier, bool add, uint256 newThreshold, uint256 validAfter);

    /// @notice Emitted when a governance change is scheduled (timelock)
    event GovernanceChangeScheduled(bytes32 indexed changeHash, uint256 validAfter);

    /// @notice Emitted when a governance change is executed
    event GovernanceChangeExecuted(bytes32 indexed changeHash);

    // Legacy events (backward compatibility — emit alongside canonical events during transition)
    event SealUsed(bytes32 indexed sealId, bytes32 commitment);
    event CrossChainLock(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, bytes32 destinationChain, bytes destinationOwner, uint256 timestamp);

    // ==================== Errors ====================

    error SanadAlreadyConsumed();
    error SanadAlreadyLocked();
    error TimeoutNotExpired();
    error SanadAlreadyMinted();
    error RefundAlreadyClaimed();
    error NotOwner();
    error ZeroAddress();
    error InvalidProof();
    error NullifierAlreadyRegistered();
    error LockEventAlreadyRecorded();
    error Unauthorized();
    error CommitmentNotAnchored();
    error SanadNotFound();
    error TimelockNotExpired();
    // Mint-authentication errors (RFC-0012 §9)
    error InvalidMintRequest();
    error InsufficientSignatures();
    error InvalidVerifierSignature();
    error MalformedSignature();
    error AttestationExpired();
    error InvalidThreshold();

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // ==================== Constructor ====================

    /// @notice Seed the verifier set with a single verifier and threshold `M = 1`
    ///         (RFC-0012 §9.3 ETH fast-track). Rotation to M-of-N needs no ABI change.
    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier address");
        owner = msg.sender;

        isVerifier[_verifier] = true;
        verifiers.push(_verifier);
        threshold = 1;

        emit OwnershipTransferred(address(0), msg.sender);
        emit VerifierAdded(_verifier);
        emit ThresholdUpdated(1);
    }

    // ==================== Verifier set / ownership governance (OFF the mint path) ====================

    /// @notice Schedule ownership transfer with timelock
    function schedule_ownership_transfer(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert("New owner cannot be zero address");

        pendingOwner = newOwner;
        pendingOwnerValidAfter = block.timestamp + TIMELOCK_PERIOD;

        emit GovernanceChangeScheduled(
            keccak256(abi.encodePacked("ownership", newOwner, pendingOwnerValidAfter)),
            pendingOwnerValidAfter
        );
    }

    /// @notice Execute scheduled ownership transfer (after timelock expires)
    function execute_ownership_transfer() external {
        if (pendingOwner == address(0)) revert("No pending ownership transfer");
        if (block.timestamp < pendingOwnerValidAfter) revert TimelockNotExpired();

        address newOwner = pendingOwner;
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;

        pendingOwner = address(0);
        pendingOwnerValidAfter = 0;

        emit GovernanceChangeExecuted(keccak256(abi.encodePacked("ownership", newOwner)));
    }

    /// @notice Schedule a verifier-set update (add/remove a verifier and set threshold) with timelock.
    /// @dev Governance touches ONLY the verifier set — never a per-mint proof root (RFC-0012 §9.3).
    ///      `newThreshold` is applied on execute and validated against the resulting set size.
    function schedule_verifier_update(address verifier, bool add, uint256 newThreshold) external onlyOwner {
        if (verifier == address(0)) revert ZeroAddress();

        pendingVerifierUpdate = PendingVerifierUpdate({
            verifier: verifier,
            add: add,
            newThreshold: newThreshold,
            validAfter: block.timestamp + TIMELOCK_PERIOD,
            active: true
        });

        emit VerifierUpdateScheduled(verifier, add, newThreshold, block.timestamp + TIMELOCK_PERIOD);
    }

    /// @notice Execute a scheduled verifier-set update (after timelock expires).
    function execute_verifier_update() external onlyOwner {
        PendingVerifierUpdate memory p = pendingVerifierUpdate;
        if (!p.active) revert("No pending verifier update");
        if (block.timestamp < p.validAfter) revert TimelockNotExpired();

        if (p.add) {
            if (!isVerifier[p.verifier]) {
                isVerifier[p.verifier] = true;
                verifiers.push(p.verifier);
                emit VerifierAdded(p.verifier);
            }
        } else {
            if (isVerifier[p.verifier]) {
                isVerifier[p.verifier] = false;
                _remove_verifier(p.verifier);
                emit VerifierRemoved(p.verifier);
            }
        }

        // Threshold must be a valid M-of-N over the resulting set.
        if (p.newThreshold == 0 || p.newThreshold > verifiers.length) revert InvalidThreshold();
        threshold = p.newThreshold;
        emit ThresholdUpdated(p.newThreshold);

        delete pendingVerifierUpdate;
    }

    function _remove_verifier(address verifier) internal {
        uint256 len = verifiers.length;
        for (uint256 i = 0; i < len; i++) {
            if (verifiers[i] == verifier) {
                verifiers[i] = verifiers[len - 1];
                verifiers.pop();
                return;
            }
        }
    }

    /// @notice Number of verifiers currently in the set.
    function verifier_count() external view returns (uint256) {
        return verifiers.length;
    }

    /// @notice Whether an address is an authorized verifier.
    function is_verifier(address account) external view returns (bool) {
        return isVerifier[account];
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
        sealOwners[sealId] = msg.sender; // Set seal owner

        emit SanadCreated(sealId, commitment, msg.sender, block.timestamp);
        emit CommitmentAnchored(commitment, sealId, msg.sender, block.timestamp);
        emit SealUsed(sealId, commitment); // Legacy

        return true;
    }

    /// @notice Consume a seal (mark as used, register nullifier)
    /// @dev Requires seal owner signature to prevent arbitrary consumption
    function consume_seal(bytes32 sealId, bytes32 nullifier) external {
        if (usedSeals[sealId]) revert SanadAlreadyConsumed();
        if (sealOwners[sealId] != msg.sender) revert NotOwner();
        if (nullifier != bytes32(0) && nullifiers[nullifier]) revert NullifierAlreadyRegistered();

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

    /// @notice Lock a Sanad for cross-chain transfer
    function lock_sanad(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 destinationChain,
        bytes calldata destinationOwner
    ) external {
        _lock_sanad_internal(sanadId, commitment, destinationChain, destinationOwner, SanadMetadata({
            assetClass: ASSET_CLASS_UNSPECIFIED,
            assetId: bytes32(0),
            metadataHash: bytes32(0),
            proofSystem: PROOF_SYSTEM_UNSPECIFIED
        }));
    }

    /// @notice Lock a Sanad with archival metadata (metadata is NOT on the mint hot path)
    function lock_sanad_with_metadata(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 destinationChain,
        bytes calldata destinationOwner,
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem
    ) external {
        _lock_sanad_internal(sanadId, commitment, destinationChain, destinationOwner, SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem
        }));
    }

    function _lock_sanad_internal(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 destinationChain,
        bytes calldata destinationOwner,
        SanadMetadata memory metadata
    ) internal {
        (uint256 lockTimestamp, bool lockRefunded) = (locks[sanadId].timestamp, locks[sanadId].refunded);
        if (lockTimestamp != 0 && !lockRefunded) revert SanadAlreadyLocked();
        if (usedSeals[sanadId]) revert SanadAlreadyConsumed();

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

    // ==================== Verifier-attested destination mint (RFC-0012 §3 / §9) ====================

    /// @notice Mint (materialize) a Sanad on this destination chain.
    /// @dev THIN REGISTRY. Cross-chain validity is decided off-chain; authenticity here is a set
    ///      of verifier signatures over the frozen §9.2 attestation digest. There is NO proof root,
    ///      state root, Merkle proof, or leaf index. Uniqueness of `sanadId` / `nullifier` /
    ///      `lockEventId` is enforced on-chain.
    /// @param sanadId Unique sanad identifier; primary duplicate-mint key.
    /// @param commitment Commitment binding the sanad content/ownership.
    /// @param sourceChain keccak256("csv.chain.<src>") — the chain the sanad was locked on.
    /// @param destinationOwner Recipient identity bytes; the full bytes are emitted, only the hash is stored.
    /// @param lockEventId Identity of the source-chain lock event; duplicate-source-lock + settlement key.
    /// @param nullifier Replay nullifier consumed by the source seal.
    /// @param attestationExpiry u64 unix seconds; 0 = no expiry. Bound over the digest (§9.2).
    /// @param verifierSignatures `bytes[]` of 65-byte secp256k1 signatures over the §9.2 digest.
    function mint_sanad(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 sourceChain,
        bytes calldata destinationOwner,
        bytes32 lockEventId,
        bytes32 nullifier,
        uint64 attestationExpiry,
        bytes[] calldata verifierSignatures
    ) external returns (bool) {
        // Field sanity: every real mint carries non-zero replay keys.
        if (
            sanadId == bytes32(0) ||
            commitment == bytes32(0) ||
            sourceChain == bytes32(0) ||
            lockEventId == bytes32(0) ||
            nullifier == bytes32(0)
        ) revert InvalidMintRequest();

        // §9.2 expiry bound.
        if (attestationExpiry != 0 && block.timestamp > attestationExpiry) revert AttestationExpired();

        // On-chain anti-replay domain (RFC-0012 §3): reject if any uniqueness key is already taken.
        if (mintedSanads[sanadId]) revert SanadAlreadyMinted();
        if (nullifiers[nullifier]) revert NullifierAlreadyRegistered();
        if (usedLockEvents[lockEventId]) revert LockEventAlreadyRecorded();

        bytes32 destinationOwnerHash = keccak256(destinationOwner);

        // §9 authentication: verify M-of-N verifier signatures over the frozen §9.2 digest.
        bytes32 digest = mint_attestation_digest(
            sanadId,
            commitment,
            sourceChain,
            destinationOwnerHash,
            lockEventId,
            nullifier,
            attestationExpiry
        );
        _require_verifier_threshold(digest, verifierSignatures);

        // Record the mint and consume the replay keys.
        mintedSanads[sanadId] = true;
        nullifiers[nullifier] = true;
        usedLockEvents[lockEventId] = true;

        mintRecords[sanadId] = MintRecord({
            commitment: commitment,
            sourceChain: sourceChain,
            destinationOwnerHash: destinationOwnerHash,
            lockEventId: lockEventId,
            nullifier: nullifier,
            mintedAt: block.timestamp
        });

        sanadStates[sanadId] = SanadState.Minted;
        sanadMintedAt[sanadId] = block.timestamp;
        sanadLastTx[sanadId] = lockEventId;

        emit SanadMinted(sanadId, lockEventId, nullifier, commitment, sourceChain, destinationOwner, block.timestamp);
        emit NullifierRegistered(nullifier, sanadId, sourceChain, block.timestamp);

        return true;
    }

    /// @notice Compute the frozen §9.2 mint attestation digest for a mint request.
    /// @dev SHA-256 over the fixed 287-byte preimage:
    ///      "csv.mint.attestation.v1" (23) || destinationChainId (32) || destinationContract (32)
    ///      || sanadId (32) || commitment (32) || sourceChain (32) || keccak256(destinationOwner) (32)
    ///      || lockEventId (32) || nullifier (32) || attestationExpiry (u64 big-endian, 8).
    ///      `destinationChainId` = CHAIN_ETHEREUM; `destinationContract` = this contract's address
    ///      left-zero-padded to 32 bytes (EVM canonical form). Exposed as a view so operators and
    ///      the off-chain adapter can reproduce the exact digest they must sign.
    function mint_attestation_digest(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 sourceChain,
        bytes32 destinationOwnerHash,
        bytes32 lockEventId,
        bytes32 nullifier,
        uint64 attestationExpiry
    ) public view returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            MINT_ATTESTATION_DOMAIN,                       // 23 bytes
            CHAIN_ETHEREUM,                                // destinationChainId (32)
            bytes32(uint256(uint160(address(this)))),      // destinationContract (32, left-padded address)
            sanadId,                                       // 32
            commitment,                                    // 32
            sourceChain,                                   // 32
            destinationOwnerHash,                          // 32
            lockEventId,                                   // 32
            nullifier,                                     // 32
            attestationExpiry                              // 8 bytes, u64 big-endian
        );
        return sha256(preimage);
    }

    /// @notice Require at least `threshold` DISTINCT valid verifier signatures over `digest`.
    /// @dev Every signature MUST recover to an authorized verifier (invalid signer => revert);
    ///      duplicate signatures from the same verifier are counted once.
    function _require_verifier_threshold(bytes32 digest, bytes[] calldata sigs) internal view {
        uint256 m = threshold;
        if (sigs.length < m) revert InsufficientSignatures();

        address[] memory seen = new address[](sigs.length);
        uint256 count = 0;

        for (uint256 i = 0; i < sigs.length; i++) {
            address recovered = _recover_verifier(digest, sigs[i]);
            if (recovered == address(0) || !isVerifier[recovered]) revert InvalidVerifierSignature();

            bool duplicate = false;
            for (uint256 j = 0; j < count; j++) {
                if (seen[j] == recovered) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;

            seen[count] = recovered;
            count++;
        }

        if (count < m) revert InsufficientSignatures();
    }

    /// @notice Recover the signer of a 65-byte secp256k1 signature (r||s||v) over `digest`.
    /// @dev Enforces low-s and canonical v to reject malleable encodings.
    function _recover_verifier(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert MalformedSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        // Reject high-s (EIP-2 malleability guard).
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert MalformedSignature();
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) revert MalformedSignature();

        return ecrecover(digest, v, r, s);
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

    /// @notice Register a nullifier for replay protection.
    /// @dev GATED to the verifier set / owner (RFC-0012: the standalone permissionless registration
    ///      let anyone pre-register a nullifier and grief a future mint). Authenticated mint folds
    ///      nullifier registration in; this remains only for authorized out-of-band registration.
    function register_nullifier(bytes32 nullifier, bytes32 sanadId, bytes32 sourceChain) external {
        if (!isVerifier[msg.sender] && msg.sender != owner) revert Unauthorized();
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

    /// @notice Record archival metadata for a Sanad (NOT on the mint hot path)
    function record_sanad_metadata(
        bytes32 sanadId,
        uint8 assetClass,
        bytes32 assetId,
        bytes32 metadataHash,
        uint8 proofSystem
    ) external {
        if (sanadStates[sanadId] == SanadState.Uncreated || sanadStates[sanadId] == SanadState.Invalid) revert SanadNotFound();

        sanadMetadata[sanadId] = SanadMetadata({
            assetClass: assetClass,
            assetId: assetId,
            metadataHash: metadataHash,
            proofSystem: proofSystem
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
            sourceChain: mintRecords[sanadId].sourceChain,
            currentChain: CHAIN_ETHEREUM,
            destinationChain: lock.destinationChain,
            state: state,
            nullifier: mintRecords[sanadId].nullifier,
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

    /// @notice Check if a source lock event has already been recorded (duplicate-mint guard)
    function is_lock_event_recorded(bytes32 lockEventId) external view returns (bool) {
        return usedLockEvents[lockEventId];
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
        bytes32 destinationChain,
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
        uint8 proofSystem
    ) {
        SanadMetadata storage metadata = sanadMetadata[sanadId];
        return (metadata.assetClass, metadata.assetId, metadata.metadataHash, metadata.proofSystem);
    }

    // ==================== Non-authoritative proof utilities (RFC-0012 §5, NOT on the mint path) ====================
    //
    // These helpers are retained ONLY as non-authoritative utilities for future on-chain SPV work
    // (RFC-0012 §9.5). They DO NOT gate mint. Note the open reconciliation item: the on-chain
    // `ProofLeafV1` below uses `bytes32` chain identity while the Rust MCE uses a 1-byte chain id,
    // so this leaf hashing MUST NOT be used to authenticate mint until that mismatch is reconciled.

    /// @notice Canonical ProofLeafV1 schema (non-authoritative; see section note).
    struct ProofLeafV1 {
        uint32 version;
        bytes32 sourceChain;
        bytes32 destinationChain;
        bytes32 sanadId;
        bytes32 commitment;
        bytes32 contentDescriptorHash;
        bytes32 sourceSealRefHash;
        bytes32 destinationOwnerHash;
        bytes32 nullifier;
        bytes32 lockEventId;
        bytes32 metadataHash;
        bytes32 proofPolicyHash;
    }

    /// @notice Compute the keccak256 hash of a ProofLeafV1 (non-authoritative utility).
    function hashProofLeafV1(ProofLeafV1 memory leaf) internal pure returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            "csv.proof.leaf.v1",
            leaf.version,
            leaf.sourceChain,
            leaf.destinationChain,
            leaf.sanadId,
            leaf.commitment,
            leaf.contentDescriptorHash,
            leaf.sourceSealRefHash,
            leaf.destinationOwnerHash,
            leaf.nullifier,
            leaf.lockEventId,
            leaf.metadataHash,
            leaf.proofPolicyHash
        );
        return keccak256(preimage);
    }

    function _verify_merkle_proof_keccak256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafIndex) internal pure returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafIndex >> i) & 1 == 0) {
                current = _hash_pair_keccak256(current, sibling);
            } else {
                current = _hash_pair_keccak256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_double_sha256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafIndex) internal pure returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafIndex >> i) & 1 == 0) {
                current = _hash_pair_double_sha256(current, sibling);
            } else {
                current = _hash_pair_double_sha256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_blake2b256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafIndex) internal view returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafIndex >> i) & 1 == 0) {
                current = _hash_pair_blake2b256(current, sibling);
            } else {
                current = _hash_pair_blake2b256(sibling, current);
            }
        }
        return current == root;
    }

    function _verify_merkle_proof_sha3_256(bytes calldata proof, bytes32 root, bytes32 leaf, uint256 leafIndex) internal view returns (bool) {
        if (proof.length == 0 || proof.length % 32 != 0) return false;
        uint256 numLevels = proof.length / 32;
        bytes32 current = leaf;
        for (uint256 i = 0; i < numLevels; i++) {
            bytes32 sibling;
            assembly { sibling := calldataload(add(proof.offset, mul(i, 32))) }
            if ((leafIndex >> i) & 1 == 0) {
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
        require(result.length == 32, "Invalid Blake2b256 result length");
        return bytes32(result);
    }

    function sha3_256(bytes memory data) internal view returns (bytes32) {
        (bool success, bytes memory result) = address(0x05).staticcall(data);
        require(success, "SHA3-256 precompile failed");
        require(result.length == 32, "Invalid SHA3-256 result length");
        return bytes32(result);
    }
}
