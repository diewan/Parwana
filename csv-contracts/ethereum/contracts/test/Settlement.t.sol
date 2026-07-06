// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// @title Source-chain escrow settlement adversarial suite (RFC-0012 §10 / TRM-ESCROW-001)
/// @dev Covers the verifier-signed settlement-receipt release model:
///  - a locked escrow releases to the operator on a valid §10 receipt (distinct SettlementReleased)
///  - the operator CANNOT self-release (authority is the verifier set, not the payout beneficiary)
///  - forged / wrong-payload / expired receipts are rejected
///  - exactly one release per lockEventId (duplicate settlement rejected)
///  - refund/timeout returns escrow when the destination mint never occurs
///  - release and refund are mutually exclusive; settling an unknown lock reverts
contract SettlementTest is Test {
    CSVSeal public csvSeal;

    // Verifier keypair — the seeded member of the §9.3 verifier set that also signs §10 receipts.
    uint256 internal constant VERIFIER_PK = 0xA11CE;
    address internal verifierAddr;

    // The proof-delivery operator: payout beneficiary, NOT a verifier.
    uint256 internal constant OPERATOR_PK = 0x0FEE;
    address internal operator;

    // A non-verifier attacker keypair.
    uint256 internal constant ATTACKER_PK = 0xBADBAD;

    address internal locker;

    bytes32 internal constant SANAD_ID = keccak256("settle-sanad-1");
    bytes32 internal constant COMMITMENT = keccak256("settle-commitment-1");
    bytes32 internal constant LOCK_EVENT_ID = keccak256("settle-lock-event-1");
    bytes32 internal constant MINT_TX_REF = keccak256("dest-mint-tx-1");

    bytes32 internal destinationChainId;
    bytes internal destinationOwner;

    uint256 internal constant ESCROW = 1 ether;

    // Local mirror of CSVSeal.SettlementReleased for vm.expectEmit.
    event SettlementReleased(
        bytes32 indexed sanadId,
        bytes32 indexed lockEventId,
        address indexed operatorPayoutAddress,
        bytes32 destinationMintTxRef,
        uint256 amount,
        uint256 timestamp
    );

    function setUp() public {
        verifierAddr = vm.addr(VERIFIER_PK);
        operator = vm.addr(OPERATOR_PK);
        locker = address(0xA11CE0C);
        csvSeal = new CSVSeal(verifierAddr);
        destinationChainId = csvSeal.CHAIN_ETHEREUM();
        destinationOwner = abi.encodePacked(address(0xD00D), "recipient-blob");
        vm.deal(locker, 10 ether);
    }

    // -------- helpers --------

    function _lockWithEscrow(bytes32 sanadId, uint256 amount) internal {
        vm.prank(locker);
        csvSeal.lock_sanad{value: amount}(sanadId, COMMITMENT, destinationChainId, destinationOwner);
    }

    function _receiptDigest(
        bytes32 sanadId,
        bytes32 lockEventId,
        bytes32 destChainId,
        bytes32 mintTxRef,
        address payout,
        uint64 expiry
    ) internal view returns (bytes32) {
        return csvSeal.settlement_receipt_digest(sanadId, lockEventId, destChainId, mintTxRef, payout, expiry);
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

    function _settle(
        bytes32 sanadId,
        bytes32 lockEventId,
        address payout,
        uint64 expiry,
        uint256 signerPk,
        address caller
    ) internal {
        bytes32 digest = _receiptDigest(sanadId, lockEventId, destinationChainId, MINT_TX_REF, payout, expiry);
        bytes[] memory sig = _sigs(signerPk, digest);
        vm.prank(caller);
        csvSeal.settle_lock(sanadId, lockEventId, destinationChainId, MINT_TX_REF, payout, expiry, sig);
    }

    // -------- acceptance: successful release --------

    /// A locked escrow releases to the operator on a valid verifier-signed receipt.
    /// The operator submits the call (pays gas) but authority is the verifier signature.
    function testSettlementReleasesEscrowToOperator() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        assertEq(address(csvSeal).balance, ESCROW);
        uint256 before = operator.balance;

        vm.expectEmit(true, true, true, true);
        emit SettlementReleased(SANAD_ID, LOCK_EVENT_ID, operator, MINT_TX_REF, ESCROW, block.timestamp);

        // Operator is the gas-payer/submitter; the verifier's key produced the authorization.
        _settle(SANAD_ID, LOCK_EVENT_ID, operator, 0, VERIFIER_PK, operator);

        assertEq(operator.balance, before + ESCROW);
        assertEq(address(csvSeal).balance, 0);
        assertTrue(csvSeal.is_settlement_released(LOCK_EVENT_ID));

        (bool released,, bytes32 mintRef, address payout, uint256 amount,) = csvSeal.settlements(LOCK_EVENT_ID);
        assertTrue(released);
        assertEq(mintRef, MINT_TX_REF);
        assertEq(payout, operator);
        assertEq(amount, ESCROW);
    }

    /// A zero-value lock still settles (state-machine only): release emits with amount 0.
    function testZeroValueLockSettles() public {
        _lockWithEscrow(SANAD_ID, 0);
        _settle(SANAD_ID, LOCK_EVENT_ID, operator, 0, VERIFIER_PK, operator);
        assertTrue(csvSeal.is_settlement_released(LOCK_EVENT_ID));
    }

    // -------- adversarial: operator self-release + forged receipts --------

    /// THE CORE INVARIANT: the operator (payout beneficiary, not a verifier) cannot self-release.
    /// A receipt "signed" by the operator's own key is rejected as an invalid verifier signature.
    function testOperatorCannotSelfRelease() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(OPERATOR_PK, digest);
        vm.prank(operator);
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
        assertEq(address(csvSeal).balance, ESCROW); // escrow untouched
    }

    /// A signature from an arbitrary non-verifier key is rejected.
    function testForgedReceiptRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(ATTACKER_PK, digest);
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }

    /// A valid verifier signature over DIFFERENT fields must not authorize this release.
    /// Signing for payout=operator but submitting payout=attacker would redirect funds — rejected.
    function testWrongPayloadReceiptRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        // Verifier signs a receipt paying `operator`...
        bytes32 signed = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, signed);
        // ...but the submitter swaps the payout beneficiary to the attacker.
        address attacker = vm.addr(ATTACKER_PK);
        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, attacker, 0, sig);
    }

    /// Empty signature vector cannot satisfy threshold M = 1.
    function testNoSignaturesRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        bytes[] memory none = new bytes[](0);
        vm.expectRevert(CSVSeal.InsufficientSignatures.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, none);
    }

    /// Expired receipts are rejected (§10 receiptExpiry).
    function testExpiredReceiptRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        vm.warp(1_000_000);
        uint64 expiry = uint64(block.timestamp - 1);
        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, expiry);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.ReceiptExpired.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, expiry, sig);
    }

    // -------- adversarial: uniqueness / one-receipt-per-lockEventId --------

    /// A second settle of the SAME sanad is rejected: the lock is already settled.
    function testDoubleSettleSameSanadRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        _settle(SANAD_ID, LOCK_EVENT_ID, operator, 0, VERIFIER_PK, operator);

        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.LockAlreadySettled.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }

    /// The lockEventId settlement domain is global: a DIFFERENT sanad reusing an already-released
    /// lockEventId is rejected (exactly one valid receipt per lockEventId, §10).
    function testDuplicateLockEventSettlementRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        _settle(SANAD_ID, LOCK_EVENT_ID, operator, 0, VERIFIER_PK, operator);

        bytes32 sanad2 = keccak256("settle-sanad-2");
        _lockWithEscrow(sanad2, ESCROW);
        bytes32 digest = _receiptDigest(sanad2, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.SettlementAlreadyReleased.selector);
        csvSeal.settle_lock(sanad2, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }

    /// Settling a lock that does not exist is rejected (e.g. a source reorg dropped the lock).
    function testSettleUnknownLockReverts() public {
        bytes32 ghost = keccak256("never-locked");
        bytes32 digest = _receiptDigest(ghost, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.SanadNotFound.selector);
        csvSeal.settle_lock(ghost, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }

    /// Zero replay keys / zero payout are rejected — no release without a lock event and beneficiary.
    function testZeroFieldsRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        bytes32 digest = _receiptDigest(SANAD_ID, bytes32(0), destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.InvalidSettlementRequest.selector);
        csvSeal.settle_lock(SANAD_ID, bytes32(0), destinationChainId, MINT_TX_REF, operator, 0, sig);

        bytes32 d2 = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, address(0), 0);
        bytes[] memory sig2 = _sigs(VERIFIER_PK, d2);
        vm.expectRevert(CSVSeal.ZeroAddress.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, address(0), 0, sig2);
    }

    // -------- refund / timeout + mutual exclusion --------

    /// When the destination mint never occurs, the locker reclaims the escrow after timeout.
    function testRefundReturnsEscrow() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        uint256 before = locker.balance;

        vm.warp(block.timestamp + csvSeal.REFUND_TIMEOUT() + 1);
        vm.prank(locker);
        csvSeal.refund_sanad(SANAD_ID, keccak256(destinationOwner));

        assertEq(locker.balance, before + ESCROW);
        assertEq(address(csvSeal).balance, 0);
    }

    /// A settled lock can never be refunded (release and refund are mutually exclusive).
    function testCannotRefundSettledLock() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        _settle(SANAD_ID, LOCK_EVENT_ID, operator, 0, VERIFIER_PK, operator);

        vm.warp(block.timestamp + csvSeal.REFUND_TIMEOUT() + 1);
        vm.prank(locker);
        vm.expectRevert(CSVSeal.LockAlreadySettled.selector);
        csvSeal.refund_sanad(SANAD_ID, keccak256(destinationOwner));
    }

    /// A refunded lock can never be settled (the escrow already went back to the locker).
    function testCannotSettleRefundedLock() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        vm.warp(block.timestamp + csvSeal.REFUND_TIMEOUT() + 1);
        vm.prank(locker);
        csvSeal.refund_sanad(SANAD_ID, keccak256(destinationOwner));

        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);
        vm.expectRevert(CSVSeal.RefundAlreadyClaimed.selector);
        csvSeal.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }

    /// Cross-deploy replay: a receipt bound to one escrow deployment does not release another.
    /// The §10 digest binds `sourceEscrowContract`, so the same fields do not verify elsewhere.
    function testCrossDeployReplayRejected() public {
        _lockWithEscrow(SANAD_ID, ESCROW);
        CSVSeal other = new CSVSeal(verifierAddr);
        vm.deal(locker, 10 ether);
        vm.prank(locker);
        other.lock_sanad{value: ESCROW}(SANAD_ID, COMMITMENT, destinationChainId, destinationOwner);

        // Digest/signature produced against the ORIGINAL escrow contract.
        bytes32 digest = _receiptDigest(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0);
        bytes[] memory sig = _sigs(VERIFIER_PK, digest);

        vm.expectRevert(CSVSeal.InvalidVerifierSignature.selector);
        other.settle_lock(SANAD_ID, LOCK_EVENT_ID, destinationChainId, MINT_TX_REF, operator, 0, sig);
    }
}
