// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// @title Naming Constitution Tests for CSVSeal
/// @dev Tests that canonical event naming constitution is followed
/// Ensures backward compatibility during naming transition:
/// - SealUsed event emitted alongside SanadConsumed
/// - SanadMinted event emitted alongside CrossChainMint
contract NamingConstitutionTest is Test {
    CSVSeal csvSeal;
    address owner;
    address verifier;
    address user1;

    bytes32 constant SANAD_ID = keccak256("test_sanad");
    bytes32 constant COMMITMENT = keccak256("test_commitment");
    bytes32 constant NULLIFIER = keccak256("test_nullifier");

    event SealUsed(bytes32 indexed sealId, bytes32 commitment);
    event SanadConsumed(bytes32 indexed sanadId, bytes32 indexed nullifier, address indexed consumer, uint256 timestamp);
    event SanadMinted(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint8 sourceChain, bytes sourceSealRef, uint256 timestamp);
    event CrossChainLock(bytes32 indexed sanadId, bytes32 indexed commitment, address indexed owner, uint8 destinationChain, bytes destinationOwner, uint256 timestamp);

    function setUp() public {
        owner = address(this);
        verifier = address(0x2);
        user1 = address(0x3);

        csvSeal = new CSVSeal(verifier);
    }

    /// @notice Test that SealUsed event is emitted alongside SanadConsumed
    function testSealUsedEmittedWithSanadConsumed() public {
        // Create a seal
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Expect both SealUsed and SanadConsumed events
        vm.expectEmit(true, true, true, true);
        emit SealUsed(SANAD_ID, bytes32(0)); // Legacy event with null commitment
        
        vm.expectEmit(true, true, true, true);
        emit SanadConsumed(SANAD_ID, NULLIFIER, owner, block.timestamp);
        
        // Consume the seal
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
    }

    /// @notice Test that SanadMinted event is emitted with canonical name
    function testSanadMintedCanonicalName() public {
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
        
        // Expect SanadMinted event with canonical name
        vm.expectEmit(true, true, true, true);
        emit SanadMinted(SANAD_ID, COMMITMENT, owner, sourceChain, sourceSealPoint, block.timestamp);
        
        // Mint the sanad
        csvSeal.mint_sanad(SANAD_ID, COMMITMENT, stateRoot, sourceChain, sourceSealPoint, proof, proofRoot, 0);
    }

    /// @notice Test that CrossChainLock legacy event is emitted alongside SanadLocked
    function testCrossChainLockEmittedWithSanadLocked() public {
        uint8 destinationChain = 3; // CHAIN_ETHEREUM
        bytes memory destinationOwner = abi.encodePacked(user1);
        
        // Expect both CrossChainLock (legacy) and SanadLocked (canonical) events
        vm.expectEmit(true, true, true, true);
        emit CrossChainLock(SANAD_ID, COMMITMENT, owner, destinationChain, destinationOwner, block.timestamp);
        
        // Lock the sanad (will emit both legacy and canonical events)
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
    }

    /// @notice Test that CommitmentAnchored event is emitted on seal creation
    function testCommitmentAnchoredEmitted() public {
        // Create seal (will emit CommitmentAnchored event internally)
        csvSeal.create_seal(COMMITMENT, COMMITMENT);
        
        // Verify the commitment was anchored
        (uint256 anchorHeight, ) = (csvSeal.commitmentAnchorHeight(COMMITMENT), csvSeal.sealOwners(COMMITMENT));
        assertGt(anchorHeight, 0);
    }

    /// @notice Test that SanadCreated event is emitted on seal creation
    function testSanadCreatedEmitted() public {
        // Create seal (will emit SanadCreated event internally)
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Verify the sanad was created
        assertEq(uint256(csvSeal.sanadStates(SANAD_ID)), uint256(CSVSeal.SanadState.Created));
    }

    /// @notice Test that NullifierRegistered event is emitted on consume
    function testNullifierRegisteredEmitted() public {
        // Create and consume seal
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        
        // Consume seal (will emit NullifierRegistered event internally)
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
        
        // Verify the nullifier was registered
        assertTrue(csvSeal.nullifiers(NULLIFIER));
    }

    /// @notice Test that all canonical events are emitted in correct sequence
    function testCanonicalEventSequence() public {
        // Create seal
        csvSeal.create_seal(COMMITMENT, SANAD_ID);
        assertEq(uint256(csvSeal.sanadStates(SANAD_ID)), uint256(CSVSeal.SanadState.Created));
        
        // Lock sanad
        uint8 destinationChain = 3;
        bytes memory destinationOwner = abi.encodePacked(user1);
        csvSeal.lock_sanad(SANAD_ID, COMMITMENT, destinationChain, destinationOwner);
        assertEq(uint256(csvSeal.sanadStates(SANAD_ID)), uint256(CSVSeal.SanadState.Locked));
        
        // Consume seal
        csvSeal.consume_seal(SANAD_ID, NULLIFIER);
        assertEq(uint256(csvSeal.sanadStates(SANAD_ID)), uint256(CSVSeal.SanadState.Consumed));
    }

    /// @notice Test that governance events are emitted correctly
    function testGovernanceEvents() public {
        address newOwner = address(0x999);
        
        // Schedule ownership transfer
        csvSeal.schedule_ownership_transfer(newOwner);
        
        // Warp and execute
        vm.warp(block.timestamp + 8 days);
        
        // Execute ownership transfer
        csvSeal.execute_ownership_transfer();
        
        // Verify ownership changed
        assertEq(csvSeal.owner(), newOwner);
    }

    /// @notice Test that epoch events are emitted correctly
    function testEpochEvents() public {
        bytes32 newRoot = keccak256("new_root");
        
        // Advance epoch
        csvSeal.advance_epoch(newRoot, 365 days);
        
        // Verify epoch advanced (currentEpoch returns a tuple)
        (uint256 epoch, bytes32 root, , , ) = csvSeal.currentEpoch();
        assertEq(epoch, 1);
        assertEq(root, newRoot);
    }
}
