//! CSV Seal Contract Bindings
//!
//! Type-safe bindings for the CSVSeal contract using Alloy.
//!
//! Regenerated from the finalized `csv-contracts/ethereum/contracts/src/CSVSeal.sol`
//! (RFC-0012 thin registry, `VERSION = 6`). The mint path is verifier-attested
//! (ABI_CONSTITUTION.md §9): `mint_sanad` carries `bytes[] verifierSignatures` over the
//! frozen §9.2 attestation digest and enforces on-chain `sanadId` / `nullifier` /
//! `lockEventId` uniqueness. There is NO proof root, state root, Merkle proof, or leaf
//! index on the mint hot path, and chain identity is `bytes32 = keccak256("csv.chain.<name>")`
//! (never a `uint8`). Names are canonical snake_case, matching the deployed contract.

#![allow(clippy::too_many_arguments)]

use alloy_sol_types::sol;

// Solidity contract ABI — mirrors the external/public surface of CSVSeal.sol.
sol! {
    #[sol(rpc)]
    contract CSVSeal {
        // ---- Protocol constants ----
        uint256 public constant VERSION = 6;

        uint8 public constant ASSET_CLASS_UNSPECIFIED = 0;
        uint8 public constant ASSET_CLASS_FUNGIBLE_TOKEN = 1;
        uint8 public constant ASSET_CLASS_NON_FUNGIBLE_TOKEN = 2;
        uint8 public constant ASSET_CLASS_PROOF_SANAD = 3;
        uint8 public constant PROOF_SYSTEM_UNSPECIFIED = 0;

        uint256 public constant REFUND_TIMEOUT = 24 hours;
        uint256 public constant TIMELOCK_PERIOD = 7 days;

        // ---- Canonical lifecycle enums (uint8 on the wire) ----
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

        enum SealState {
            Created,
            Consumed,
            Locked,
            Minted,
            Refunded
        }

        // ---- Canonical view structures ----
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

        struct SealStateView {
            bytes32 sealId;
            bytes32 sanadId;
            bytes32 commitment;
            SealState state;
            uint256 consumedAt;
            uint256 lockedAt;
        }

        // ---- Canonical events ----
        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        event SanadCreated(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint256 timestamp);
        event SanadConsumed(bytes32 indexed sanadId, bytes32 indexed nullifier, address indexed consumer, uint256 timestamp);
        event SanadLocked(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed owner,
            bytes32 destinationChain,
            bytes destinationOwner,
            uint256 timestamp
        );
        event SanadMinted(
            bytes32 indexed sanadId,
            bytes32 indexed lockEventId,
            bytes32 indexed nullifier,
            bytes32 commitment,
            bytes32 sourceChain,
            bytes destinationOwner,
            uint256 timestamp
        );
        event SanadRefunded(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed claimant,
            string reason,
            uint256 timestamp
        );
        event SanadTransferred(bytes32 indexed sanadId, address indexed from, address indexed to, uint256 timestamp);
        event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanadId, bytes32 sourceChain, uint256 timestamp);
        event CommitmentAnchored(bytes32 indexed commitment, bytes32 indexed sealId, address indexed owner, uint256 timestamp);
        event ReplayDetected(bytes32 indexed replayId, bytes32 indexed sanadId, uint256 timestamp);
        event VerifierAdded(address indexed verifier);
        event VerifierRemoved(address indexed verifier);
        event ThresholdUpdated(uint256 threshold);
        event VerifierUpdateScheduled(address indexed verifier, bool add, uint256 newThreshold, uint256 validAfter);
        event GovernanceChangeScheduled(bytes32 indexed changeHash, uint256 validAfter);
        event GovernanceChangeExecuted(bytes32 indexed changeHash);
        // Legacy events (emitted alongside canonical events during transition)
        event SealUsed(bytes32 indexed sealId, bytes32 commitment);
        event CrossChainLock(
            bytes32 indexed sanadId,
            bytes32 indexed commitment,
            address indexed owner,
            bytes32 destinationChain,
            bytes destinationOwner,
            uint256 timestamp
        );

        // ---- Errors ----
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
        error InvalidMintRequest();
        error InsufficientSignatures();
        error InvalidVerifierSignature();
        error MalformedSignature();
        error AttestationExpired();
        error InvalidThreshold();

        constructor(address _verifier);

        // ---- Verifier-set / ownership governance (OFF the mint path) ----
        function schedule_ownership_transfer(address newOwner) external;
        function execute_ownership_transfer() external;
        function schedule_verifier_update(address verifier, bool add, uint256 newThreshold) external;
        function execute_verifier_update() external;
        function verifier_count() external view returns (uint256);
        function is_verifier(address account) external view returns (bool);

        // ---- Lifecycle mutations ----
        function create_seal(bytes32 commitment, bytes32 sealId) external returns (bool);
        function consume_seal(bytes32 sealId, bytes32 nullifier) external;

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
            uint8 proofSystem
        ) external;

        // ---- Verifier-attested destination mint (RFC-0012 §3 / §9) ----
        // Thin registry: chain identity is bytes32; authenticity is `verifierSignatures`
        // over the §9.2 digest. No proof root / state root / Merkle proof / leaf index.
        function mint_sanad(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 sourceChain,
            bytes calldata destinationOwner,
            bytes32 lockEventId,
            bytes32 nullifier,
            uint64 attestationExpiry,
            bytes[] calldata verifierSignatures
        ) external returns (bool);

        // Reproduce the frozen §9.2 attestation digest the verifier signs.
        function mint_attestation_digest(
            bytes32 sanadId,
            bytes32 commitment,
            bytes32 sourceChain,
            bytes32 destinationOwnerHash,
            bytes32 lockEventId,
            bytes32 nullifier,
            uint64 attestationExpiry
        ) external view returns (bytes32);

        function refund_sanad(bytes32 sanadId, bytes32 destinationOwnerHash) external;
        function transfer_sanad(bytes32 sanadId, address newOwner) external;
        function register_nullifier(bytes32 nullifier, bytes32 sanadId, bytes32 sourceChain) external;
        function anchor_commitment(bytes32 commitment, bytes32 sealId) external;
        function record_sanad_metadata(
            bytes32 sanadId,
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem
        ) external;

        // ---- View functions ----
        function get_sanad_state(bytes32 sanadId) external view returns (SanadStateView memory);
        function get_seal_state(bytes32 sealId) external view returns (SealStateView memory);
        function is_seal_available(bytes32 sealId) external view returns (bool);
        function is_seal_consumed(bytes32 sealId) external view returns (bool);
        function is_nullifier_registered(bytes32 nullifier) external view returns (bool);
        function is_lock_event_recorded(bytes32 lockEventId) external view returns (bool);
        function is_commitment_anchored(bytes32 commitment) external view returns (bool);
        function is_sanad_minted(bytes32 sanadId) external view returns (bool);
        function can_refund(bytes32 sanadId) external view returns (bool);
        function get_lock_info(bytes32 sanadId) external view returns (
            bytes32 commitment,
            uint256 timestamp,
            bytes32 destinationChain,
            bool refunded
        );
        function get_sanad_metadata(bytes32 sanadId) external view returns (
            uint8 assetClass,
            bytes32 assetId,
            bytes32 metadataHash,
            uint8 proofSystem
        );
    }
}

// Re-export the generated types
pub use CSVSeal::*;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    /// The canonical function signature must match the finalized `mint_sanad` ABI
    /// (ABI_CONSTITUTION.md §3 / §9): `bytes32` source chain, `bytes[]` verifier
    /// signatures, no proof root / state root / leaf index.
    #[test]
    fn mint_sanad_selector_matches_finalized_abi() {
        const EXPECTED_SIGNATURE: &str =
            "mint_sanad(bytes32,bytes32,bytes32,bytes,bytes32,bytes32,uint64,bytes[])";

        assert_eq!(mint_sanadCall::SIGNATURE, EXPECTED_SIGNATURE);

        // 4-byte selector = keccak256(signature)[..4], computed independently.
        let expected_selector = &alloy_primitives::keccak256(EXPECTED_SIGNATURE.as_bytes())[..4];
        assert_eq!(
            &mint_sanadCall::SELECTOR[..],
            expected_selector,
            "mint_sanad binding selector diverged from the finalized ABI",
        );

        // Pinned to the deployed contract's compiled selector:
        //   `forge inspect src/CSVSeal.sol:CSVSeal methodIdentifiers` => mint_sanad = 0c6664f2
        //   `cast sig "mint_sanad(...)"` => 0x0c6664f2
        assert_eq!(mint_sanadCall::SELECTOR, [0x0c, 0x66, 0x64, 0xf2]);

        // Forbidden legacy shape must not be what we compile to.
        assert_ne!(
            mint_sanadCall::SIGNATURE,
            "mintSanad(bytes32,bytes32,bytes32,uint8,bytes,bytes,bytes32,uint256)",
        );
    }

    /// A mint call round-trips through ABI encode/decode with the exact field layout,
    /// proving `sourceChain` is `bytes32` and `verifierSignatures` is `bytes[]`.
    #[test]
    fn mint_sanad_call_roundtrips() {
        use alloy_primitives::{Bytes, FixedBytes};

        let call = mint_sanadCall {
            sanadId: FixedBytes::<32>::from([1u8; 32]),
            commitment: FixedBytes::<32>::from([2u8; 32]),
            sourceChain: FixedBytes::<32>::from([3u8; 32]),
            destinationOwner: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
            lockEventId: FixedBytes::<32>::from([4u8; 32]),
            nullifier: FixedBytes::<32>::from([5u8; 32]),
            attestationExpiry: 1_900_000_000u64,
            verifierSignatures: vec![Bytes::from(vec![7u8; 65]), Bytes::from(vec![8u8; 65])],
        };

        let encoded = call.abi_encode();
        // First 4 bytes are the selector; the rest is the head/tail encoding.
        assert_eq!(&encoded[..4], &mint_sanadCall::SELECTOR[..]);

        let decoded = mint_sanadCall::abi_decode(&encoded).expect("decode mint_sanad calldata");
        assert_eq!(decoded.sourceChain, call.sourceChain);
        assert_eq!(decoded.attestationExpiry, call.attestationExpiry);
        assert_eq!(decoded.verifierSignatures.len(), 2);
        assert_eq!(decoded.verifierSignatures[0].len(), 65);
    }

    /// The binding's on-chain `VERSION` constant must equal the deployed contract (6),
    /// and expose the canonical `VERSION()` getter.
    #[test]
    fn version_matches_deployed_contract() {
        let ret = VERSIONReturn {
            VERSION: alloy_primitives::U256::from(6),
        };
        assert_eq!(ret.VERSION, alloy_primitives::U256::from(6));
        assert_eq!(VERSIONCall::SIGNATURE, "VERSION()");
    }
}
