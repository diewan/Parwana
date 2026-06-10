// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// @title Adversarial Tests for CSVSeal
/// @dev Tests negative scenarios and attack vectors to ensure contract security
contract AdversarialTest is Test {
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
        // Create a seal
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // First consume should succeed
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
        
        // Second consume should fail
        vm.expectRevert(CSVSeal.SanadAlreadyConsumed.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that non-owner cannot consume seal
    function testConsumeByNonOwner() public {
        // Create a seal as owner
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Try to consume as attacker (non-owner)
        vm.prank(attacker);
        vm.expectRevert(CSVSeal.NotOwner.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that double mint is prevented
    function testDoubleMint() public {
        // Lock a sanad
        uint8 destinationChain = 3; // CHAIN_ETHEREUM
        bytes memory destinationOwner = abi.encodePacked(user1);
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
        
        // Prepare proof data
        bytes32 stateRoot = keccak256("state_root");
        uint8 sourceChain = 0; // CHAIN_BITCOIN
        bytes memory sourceSealPoint = hex"1234";
        bytes memory proof = hex"5678";
        bytes32 proofRoot = keccak256("proof_root");
        
        // Schedule and execute proof root update (bypass timelock for test by warping)
        csvSeal.schedule_proof_root_update(proofRoot);
        vm.warp(block.timestamp + 8 days);
        csvSeal.execute_proof_root_update();
        
        // First mint should succeed
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, 0);
        
        // Second mint should fail
        vm.expectRevert(CSVSeal.SanadAlreadyMinted.selector);
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, 0);
    }

    /// @notice Test that refund after mint is prevented
    function testRefundAfterMint() public {
        // Lock a sanad
        uint8 destinationChain = 3; // CHAIN_ETHEREUM
        bytes memory destinationOwner = abi.encodePacked(user1);
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
        
        // Prepare proof data
        bytes32 stateRoot = keccak256("state_root");
        uint8 sourceChain = 0; // CHAIN_BITCOIN
        bytes memory sourceSealPoint = hex"1234";
        bytes memory proof = hex"5678";
        bytes32 proofRoot = keccak256("proof_root");
        
        // Schedule and execute proof root update
        csvSeal.schedule_proof_root_update(proofRoot);
        vm.warp(block.timestamp + 8 days);
        csvSeal.execute_proof_root_update();
        
        // Mint the sanad
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, 0);
        
        // Try to refund after mint should fail
        vm.expectRevert(CSVSeal.RefundAlreadyClaimed.selector);
        csvSeal.refund_sanad(SANAD_ID, "Test refund");
    }

    /// @notice Test that double lock is prevented
    function testDoubleLock() public {
        uint8 destinationChain = 3; // CHAIN_ETHEREUM
        bytes memory destinationOwner = abi.encodePacked(user1);
        
        // First lock should succeed
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
        
        // Second lock should fail
        vm.expectRevert(CSVSeal.SanadAlreadyLocked.selector);
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
    }

    /// @notice Test that nullifier reuse is prevented
    function testNullifierReuse() public {
        // Create first seal and consume with nullifier
        bytes32 sanadId1 = keccak256("sanad_1");
        csvSeal.create_seal(COMMITMENT, sanadId1);
        csvSeal.consume_seal(sanadId1, NULLIFIER);
        
        // Create second seal
        bytes32 sanadId2 = keccak256("sanad_2");
        csvSeal.create_seal(COMMITMENT, sanadId2);
        
        // Try to consume with same nullifier should fail
        vm.expectRevert(CSVSeal.NullifierAlreadyRegistered.selector);
        csvSeal.consume_seal(sanadId2, NULLIFIER);
    }

    /// @notice Test that governance timelock prevents immediate changes
    function testGovernanceTimelock() public {
        address newOwner = address(0x999);
        
        // Schedule ownership transfer
        csvSeal.schedule_ownership_transfer(newOwner);
        
        // Try to execute immediately should fail
        vm.expectRevert(CSVSeal.TimelockNotExpired.selector);
        csvSeal.execute_ownership_transfer();
        
        // Warp forward past timelock
        vm.warp(block.timestamp + 8 days);
        
        // Execute after timelock should succeed
        csvSeal.execute_ownership_transfer();
        assertEq(csvSeal.owner(), newOwner);
    }

    /// @notice Test that epoch monotonicity is enforced
    function testEpochMonotonicity() public {
        // Advance epoch to 1
        bytes32 root1 = keccak256("root_1");
        csvSeal.advance_epoch(root1, 365 days);
        
        // Try to advance to epoch 3 (skip 2) should fail
        bytes32 root3 = keccak256("root_3");
        vm.expectRevert(); // Will fail due to monotonic check
        csvSeal.advance_epoch(root3, 365 days);
        
        // Advance to epoch 2 should succeed
        bytes32 root2 = keccak256("root_2");
        csvSeal.advance_epoch(root2, 365 days);
    }

    /// @notice Test that arbitrary owner cannot consume seal
    function testArbitraryOwnerConsume() public {
        // Create seal as user1
        vm.prank(user1);
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Try to consume as attacker should fail
        vm.prank(attacker);
        vm.expectRevert(CSVSeal.NotOwner.selector);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that seal ownership is tracked correctly
    function testSealOwnershipTracking() public {
        // Create seal as user1
        vm.prank(user1);
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Verify ownership
        assertEq(csvSeal.sealOwners(SANAD_ID), user1);
        
        // Transfer ownership (if implemented) or verify only owner can consume
        vm.prank(user1);
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that proof root update requires authorization
    function testProofRootUpdateAuthorization() public {
        bytes32 newRoot = keccak256("new_root");
        
        // Try to schedule update as non-verifier should fail
        vm.prank(attacker);
        vm.expectRevert(CSVSeal.Unauthorized.selector);
        csvSeal.schedule_proof_root_update(newRoot);
        
        // Schedule as owner should succeed
        csvSeal.schedule_proof_root_update(newRoot);
        
        // Warp past timelock and execute
        vm.warp(block.timestamp + 8 days);
        csvSeal.execute_proof_root_update();
        
        assertEq(csvSeal.trustedProofRoot(), newRoot);
    }

    /// @notice Test that invalid proof root is rejected
    function testInvalidProofRoot() public {
        bytes32 invalidRoot = bytes32(0);
        
        vm.expectRevert(CSVSeal.InvalidProofRoot.selector);
        csvSeal.schedule_proof_root_update(invalidRoot);
    }

    /// @notice Test that zero address is rejected in ownership transfer
    function testZeroAddressOwnershipTransfer() public {
        vm.expectRevert("New owner cannot be zero address");
        csvSeal.schedule_ownership_transfer(address(0));
    }

    /// @notice Test that multisig requires threshold
    function testMultisigThreshold() public {
        // Enable multisig with threshold 2
        csvSeal.enable_multisig(2);
        
        // Add signers
        csvSeal.add_multisig_signer(user1);
        csvSeal.add_multisig_signer(user2);
        
        bytes32 changeHash = keccak256("test_change");
        
        // Approve with only 1 signer should not meet threshold
        vm.prank(user1);
        csvSeal.approve_governance_change(changeHash);
        
        // Try to execute should fail
        vm.prank(user1);
        vm.expectRevert(CSVSeal.MultisigThresholdNotMet.selector);
        csvSeal.execute_multisig_change(changeHash);
        
        // Approve with second signer
        vm.prank(user2);
        csvSeal.approve_governance_change(changeHash);
        
        // Execute should succeed
        vm.prank(user1);
        csvSeal.execute_multisig_change(changeHash);
    }
}
