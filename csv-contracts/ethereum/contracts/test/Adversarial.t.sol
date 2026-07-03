// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// @title Verifier-attested mint adversarial suite (RFC-0012 §9 / TRM-ETH-CTR-001)
/// @dev Covers the thin-registry mint authenticity model:
///  - happy mint on a FRESH deploy with a valid attestation and NO proof-root install
///  - forged / insufficient / malformed / expired attestations are rejected
///  - duplicate sanadId / nullifier / lockEventId are each rejected
///  - the §9.2 digest binds destination chain + contract (cross-deploy replay is rejected)
contract AdversarialMintTest is Test {
    CSVSeal public csvSeal;

    // Verifier keypair. The address is the seeded member of the §9.3 verifier set.
    uint256 internal constant VERIFIER_PK = 0xA11CE;
    address internal verifierAddr;

    // A non-verifier attacker keypair.
    uint256 internal constant ATTACKER_PK = 0xBADBAD;

    bytes32 internal constant SANAD_ID = keccak256("sanad-1");
    bytes32 internal constant COMMITMENT = keccak256("commitment-1");
    bytes32 internal constant LOCK_EVENT_ID = keccak256("lock-event-1");
    bytes32 internal constant NULLIFIER = keccak256("nullifier-1");

    bytes32 internal sourceChain;
    bytes internal destinationOwner;

    // Local mirror of CSVSeal.SanadMinted for vm.expectEmit.
    event SanadMinted(
        bytes32 indexed sanadId,
        bytes32 indexed lockEventId,
        bytes32 indexed nullifier,
        bytes32 commitment,
        bytes32 sourceChain,
        bytes destinationOwner,
        uint256 timestamp
    );

    function setUp() public {
        verifierAddr = vm.addr(VERIFIER_PK);
        csvSeal = new CSVSeal(verifierAddr);
        sourceChain = csvSeal.CHAIN_BITCOIN();
        destinationOwner = abi.encodePacked(address(0xD00D), "recipient-blob");
    }

    // -------- helpers --------

    function _digest(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 srcChain,
        bytes memory destOwner,
        bytes32 lockEventId,
        bytes32 nullifier,
        uint64 expiry
    ) internal view returns (bytes32) {
        return csvSeal.mint_attestation_digest(
            sanadId,
            commitment,
            srcChain,
            keccak256(destOwner),
            lockEventId,
            nullifier,
            expiry
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sigs(uint256 pk, bytes32 digest) internal pure returns (bytes[] memory) {
        bytes[] memory out = new bytes[](1);
        out[0] = _sign(pk, digest);
        return out;
    }

    function _mint(
        bytes32 sanadId,
        bytes32 commitment,
        bytes32 srcChain,
        bytes memory destOwner,
        bytes32 lockEventId,
        bytes32 nullifier,
        uint64 expiry,
        uint256 signerPk
    ) internal returns (bool) {
        bytes32 digest = _digest(sanadId, commitment, srcChain, destOwner, lockEventId, nullifier, expiry);
        return csvSeal.mint_sanad(
            sanadId, commitment, srcChain, destOwner, lockEventId, nullifier, expiry, _sigs(signerPk, digest)
        );
    }

    // -------- acceptance: happy mint on a fresh deploy --------

    /// A fresh deploy can mint with a valid attestation and no proof-root installation.
    function testFreshDeployHappyMint() public {
        // The gas-payer is an arbitrary operator, NOT the verifier — authority travels in the payload.
        vm.prank(address(0xEEEE));
        bool ok = _mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, VERIFIER_PK);
        assertTrue(ok);

        assertTrue(csvSeal.is_sanad_minted(SANAD_ID));
        assertTrue(csvSeal.is_nullifier_registered(NULLIFIER));
        assertTrue(csvSeal.is_lock_event_recorded(LOCK_EVENT_ID));

        (bytes32 c, bytes32 sc, bytes32 doh, bytes32 le, bytes32 nf, uint256 mintedAt) = csvSeal.mintRecords(SANAD_ID);
        assertEq(c, COMMITMENT);
        assertEq(sc, sourceChain);
        assertEq(doh, keccak256(destinationOwner)); // stores the hash, not the full bytes
        assertEq(le, LOCK_EVENT_ID);
        assertEq(nf, NULLIFIER);
        assertGt(mintedAt, 0);
    }

    /// SanadMinted must emit the FULL destinationOwner bytes with settlement-indexed topics.
    function testSanadMintedEmitsFullOwnerBytes() public {
        vm.expectEmit(true, true, true, true);
        emit SanadMinted(
            SANAD_ID, LOCK_EVENT_ID, NULLIFIER, COMMITMENT, sourceChain, destinationOwner, block.timestamp
        );
        _mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, VERIFIER_PK);
    }

    // -------- acceptance: forged / insufficient signatures --------

    /// Mint reverts on a signature from a key that is not in the verifier set.
    function testForgedAttestationRejected() public {
        bytes32 digest = _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0);
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        csvSeal.mint_sanad(
            SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, _sigs(ATTACKER_PK, digest)
        );
    }

    /// A valid verifier signature over a DIFFERENT payload must not authorize this mint.
    function testWrongPayloadSignatureRejected() public {
        // Sign a digest for a different sanadId, then submit it against SANAD_ID.
        bytes32 wrongDigest = _digest(keccak256("other-sanad"), COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0);
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        csvSeal.mint_sanad(
            SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, _sigs(VERIFIER_PK, wrongDigest)
        );
    }

    /// Empty signature vector cannot satisfy threshold M = 1.
    function testNoSignaturesRejected() public {
        bytes[] memory none = new bytes[](0);
        vm.expectRevert(CSVSeal.InsufficientSignatures.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, none);
    }

    /// Malformed (wrong-length) signatures are rejected.
    function testMalformedSignatureRejected() public {
        bytes[] memory bad = new bytes[](1);
        bad[0] = hex"1234"; // not 65 bytes
        vm.expectRevert(CSVSeal.MalformedSignature.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, bad);
    }

    /// Duplicate signatures from a single verifier do not reach an M=2 threshold.
    function testDuplicateSignatureDoesNotReachThreshold() public {
        // Add a second verifier and require M = 2.
        uint256 pk2 = 0xC0FFEE;
        address v2 = vm.addr(pk2);
        csvSeal.schedule_verifier_update(v2, true, 2);
        vm.warp(block.timestamp + 8 days);
        csvSeal.execute_verifier_update();
        assertEq(csvSeal.threshold(), 2);

        bytes32 digest = _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0);
        bytes[] memory dup = new bytes[](2);
        dup[0] = _sign(VERIFIER_PK, digest);
        dup[1] = _sign(VERIFIER_PK, digest); // same signer twice
        vm.expectRevert(CSVSeal.InsufficientSignatures.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, dup);

        // Two DISTINCT verifier signatures satisfy the threshold.
        bytes[] memory both = new bytes[](2);
        both[0] = _sign(VERIFIER_PK, digest);
        both[1] = _sign(pk2, digest);
        assertTrue(csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, both));
    }

    // -------- acceptance: expiry --------

    /// Expired attestations are rejected (§9.2 attestationExpiry).
    function testExpiredAttestationRejected() public {
        vm.warp(1_000_000);
        uint64 expiry = uint64(block.timestamp - 1);
        bytes32 digest = _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, expiry);
        vm.expectRevert(CSVSeal.AttestationExpired.selector);
        csvSeal.mint_sanad(
            SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, expiry, _sigs(VERIFIER_PK, digest)
        );
    }

    /// A non-expired attestation with an explicit future expiry mints.
    function testFutureExpiryMints() public {
        vm.warp(1_000_000);
        uint64 expiry = uint64(block.timestamp + 3600);
        assertTrue(_mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, expiry, VERIFIER_PK));
    }

    // -------- acceptance: duplicate uniqueness keys --------

    /// Duplicate sanadId is rejected even with a fresh valid attestation.
    function testDuplicateSanadRejected() public {
        _mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, VERIFIER_PK);
        // Change nullifier + lockEventId so ONLY the sanadId collision is exercised.
        bytes32 le2 = keccak256("le2");
        bytes32 nf2 = keccak256("nf2");
        // Precompute sigs BEFORE expectRevert so the digest view call is not the reverting call.
        bytes[] memory sig = _sigs(VERIFIER_PK, _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, le2, nf2, 0));
        vm.expectRevert(CSVSeal.SanadAlreadyMinted.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, le2, nf2, 0, sig);
    }

    /// Duplicate nullifier is rejected.
    function testDuplicateNullifierRejected() public {
        _mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, VERIFIER_PK);
        bytes32 sanad2 = keccak256("sanad2");
        bytes32 le2 = keccak256("le2");
        bytes[] memory sig = _sigs(VERIFIER_PK, _digest(sanad2, COMMITMENT, sourceChain, destinationOwner, le2, NULLIFIER, 0));
        vm.expectRevert(CSVSeal.NullifierAlreadyRegistered.selector);
        csvSeal.mint_sanad(sanad2, COMMITMENT, sourceChain, destinationOwner, le2, NULLIFIER, 0, sig);
    }

    /// Duplicate lockEventId is rejected.
    function testDuplicateLockEventRejected() public {
        _mint(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, VERIFIER_PK);
        bytes32 sanad2 = keccak256("sanad2");
        bytes32 nf2 = keccak256("nf2");
        bytes[] memory sig = _sigs(VERIFIER_PK, _digest(sanad2, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, nf2, 0));
        vm.expectRevert(CSVSeal.LockEventAlreadyRecorded.selector);
        csvSeal.mint_sanad(sanad2, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, nf2, 0, sig);
    }

    /// Zero replay keys are rejected — no mint without a nullifier and lock event.
    function testZeroKeysRejected() public {
        bytes32 digest = _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, bytes32(0), NULLIFIER, 0);
        vm.expectRevert(CSVSeal.InvalidMintRequest.selector);
        csvSeal.mint_sanad(
            SANAD_ID, COMMITMENT, sourceChain, destinationOwner, bytes32(0), NULLIFIER, 0, _sigs(VERIFIER_PK, digest)
        );
    }

    // -------- acceptance: cross-deploy replay --------

    /// A signature bound to one deployment must not authorize a mint on a second deployment.
    /// The §9.2 digest binds `destinationContract`, so the same fields signed for `csvSeal`
    /// do not verify against a second CSVSeal instance.
    function testCrossDeployReplayRejected() public {
        CSVSeal other = new CSVSeal(verifierAddr);

        // Digest/signature produced against the ORIGINAL contract.
        bytes32 digest = _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);

        // Replaying it against `other` must fail: `other`'s digest binds `other`'s address.
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        other.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, sig);
    }

    // -------- gated nullifier registration --------

    /// register_nullifier is no longer permissionless: a non-verifier cannot pre-register.
    function testRegisterNullifierGated() public {
        vm.prank(address(0x1234));
        vm.expectRevert(CSVSeal.Unauthorized.selector);
        csvSeal.register_nullifier(NULLIFIER, SANAD_ID, sourceChain);
    }

    /// A verifier may still register a nullifier out-of-band, and it then blocks a mint reusing it.
    function testVerifierCanRegisterNullifier() public {
        vm.prank(verifierAddr);
        csvSeal.register_nullifier(NULLIFIER, SANAD_ID, sourceChain);
        assertTrue(csvSeal.is_nullifier_registered(NULLIFIER));

        bytes[] memory sig = _sigs(VERIFIER_PK, _digest(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0));
        vm.expectRevert(CSVSeal.NullifierAlreadyRegistered.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, sourceChain, destinationOwner, LOCK_EVENT_ID, NULLIFIER, 0, sig);
    }
}
