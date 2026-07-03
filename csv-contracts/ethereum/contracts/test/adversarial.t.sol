// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// @title Lifecycle Adversarial Tests for CSVSeal
/// @dev Tests negative scenarios and attack vectors for the seal/lock/refund lifecycle.
///      Mint-authentication adversarial coverage lives in Adversarial.t.sol
///      (AdversarialMintTest). Proof-root / governance-epoch / multisig tests were removed
///      with those subsystems (TRM-ETH-CTR-001 / RFC-0012).
contract LifecycleAdversarialTest is Test {
    CSVSeal csvSeal;
    address owner;
    address attacker;
    address verifier;
    address user1;
    address user2;

    bytes32 constant SANAD_ID = keccak256("test_sanad");
    bytes32 constant COMMITMENT = keccak256("test_commitment");
    bytes32 constant NULLIFIER = keccak256("test_nullifier");

    function setUp() public {
        owner = address(this);
        attacker = address(0x1);
        verifier = address(0x2);
        user1 = address(0x3);
        user2 = address(0x4);

        csvSeal = new CSVSeal(verifier);
    }

    /// @notice Test that double consume is prevented
    function testDoubleConsume() public {
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);

        vm.expectRevert(CSVSeal.SanadAlreadyConsumed.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that non-owner cannot consume seal
    function testConsumeByNonOwner() public {
        csvSeal.create_seal(COMMITMENT, SANAD_ID);

        vm.prank(attacker);
        vm.expectRevert(CSVSeal.NotOwner.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that double lock is prevented
    function testDoubleLock() public {
        bytes32 uniqueSanadId = keccak256("double_lock_sanad");
        bytes32 uniqueCommitment = keccak256("double_lock_commitment");

        bytes32 destinationChain = csvSeal.CHAIN_ETHEREUM();
        bytes memory destinationOwner = abi.encodePacked(user1);

        csvSeal.lock_sanad(uniqueSanadId, uniqueCommitment, destinationChain, destinationOwner);

        vm.expectRevert(CSVSeal.SanadAlreadyLocked.selector);
        csvSeal.lock_sanad(uniqueSanadId, uniqueCommitment, destinationChain, destinationOwner);
    }

    /// @notice Test that nullifier reuse is prevented across consumes
    function testNullifierReuse() public {
        bytes32 sanadId1 = keccak256("sanad_1");
        bytes32 commitment1 = keccak256("commitment_1");
        csvSeal.create_seal(commitment1, sanadId1);
        csvSeal.consume_seal(sanadId1, NULLIFIER);

        assertTrue(csvSeal.nullifiers(NULLIFIER));

        bytes32 sanadId2 = keccak256("sanad_2");
        bytes32 commitment2 = keccak256("commitment_2");
        csvSeal.create_seal(commitment2, sanadId2);

        vm.expectRevert(CSVSeal.NullifierAlreadyRegistered.selector);
        csvSeal.consume_seal(sanadId2, NULLIFIER);
    }

    /// @notice Test that governance timelock prevents immediate ownership changes
    function testGovernanceTimelock() public {
        address newOwner = address(0x999);

        csvSeal.schedule_ownership_transfer(newOwner);

        // Immediate execute must fail (timelock not expired).
        vm.expectRevert(CSVSeal.TimelockNotExpired.selector);
        csvSeal.execute_ownership_transfer();

        vm.warp(block.timestamp + 8 days);

        csvSeal.execute_ownership_transfer();
        assertEq(csvSeal.owner(), newOwner);
    }

    /// @notice Test that arbitrary caller cannot consume a seal it does not own
    function testArbitraryOwnerConsume() public {
        vm.prank(user1);
        csvSeal.create_seal(COMMITMENT, SANAD_ID);

        vm.prank(attacker);
        vm.expectRevert(CSVSeal.NotOwner.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that seal ownership is tracked correctly
    function testSealOwnershipTracking() public {
        vm.prank(user1);
        csvSeal.create_seal(COMMITMENT, SANAD_ID);

        assertEq(csvSeal.sealOwners(SANAD_ID), user1);

        vm.prank(user1);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that zero address is rejected in ownership transfer
    function testZeroAddressOwnershipTransfer() public {
        vm.expectRevert("New owner cannot be zero address");
        csvSeal.schedule_ownership_transfer(address(0));
    }

    /// @notice Verifier-set rotation is timelocked and off the mint path
    function testVerifierRotationTimelock() public {
        address v2 = address(0x5);

        csvSeal.schedule_verifier_update(v2, true, 1);

        // Immediate execute must fail.
        vm.expectRevert(CSVSeal.TimelockNotExpired.selector);
        csvSeal.execute_verifier_update();

        vm.warp(block.timestamp + 8 days);
        csvSeal.execute_verifier_update();

        assertTrue(csvSeal.is_verifier(v2));
        assertEq(csvSeal.verifier_count(), 2);
    }

    /// @notice Non-owner cannot schedule a verifier-set update
    function testVerifierRotationOnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert("Only owner can call this function");
        csvSeal.schedule_verifier_update(address(0x5), true, 1);
    }
}
