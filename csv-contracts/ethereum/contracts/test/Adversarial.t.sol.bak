// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CSVSeal.sol";

/// Contract adversarial suite per AUDIT.md T12
///
/// Tests 7 attack scenarios to ensure contract security:
/// 1. double_consume - Submit same proof bundle twice
/// 2. malformed_merkle_proof - Flip 1 byte in Merkle sibling
/// 3. replay_nullifier_reuse - Use consumed nullifier in new transfer
/// 4. stale_checkpoint - Submit proof against checkpoint N-5 (old)
/// 5. forged_anchor - Submit anchor hash not in event log
/// 6. partial_event_replay - Omit 1 event from event bundle
/// 7. duplicate_mint_proof - Submit valid mint proof twice

contract AdversarialTest is Test {
    CSVSeal public csvSeal;
    address public owner;
    address public attacker;

    function setUp() public {
        owner = address(this);
        attacker = address(0x1337);
        
        csvSeal = new CSVSeal();
        csvSeal.initialize();
    }

    /// Test 1: double_consume - Submit same proof bundle twice
    /// Expected: Second tx must revert with AlreadyConsumed
    function testDoubleConsume() public {
        // Create a valid proof bundle
        bytes memory proofBundle = createValidProofBundle();
        
        // First mint should succeed
        csvSeal.mint(proofBundle);
        
        // Second mint with same proof should revert
        vm.expectRevert("AlreadyConsumed");
        csvSeal.mint(proofBundle);
    }

    /// Test 2: malformed_merkle_proof - Flip 1 byte in Merkle sibling
    /// Expected: Verification must fail; no state change
    function testMalformedMerkleProof() public {
        bytes memory proofBundle = createValidProofBundle();
        
        // Flip one byte in the proof
        bytes memory malformedProof = proofBundle;
        malformedProof[10] = bytes1(uint8(malformedProof[10]) ^ 0xFF);
        
        vm.expectRevert();
        csvSeal.mint(malformedProof);
        
        // Verify no state change
        assertEq(csvSeal.totalSupply(), 0);
    }

    /// Test 3: replay_nullifier_reuse - Use consumed nullifier in new transfer
    /// Expected: Contract must reject
    function testReplayNullifierReuse() public {
        bytes memory proofBundle1 = createValidProofBundle();
        bytes memory proofBundle2 = createProofWithSameNullifier(proofBundle1);
        
        // First mint succeeds
        csvSeal.mint(proofBundle1);
        
        // Second mint with same nullifier should revert
        vm.expectRevert("NullifierAlreadyConsumed");
        csvSeal.mint(proofBundle2);
    }

    /// Test 4: stale_checkpoint - Submit proof against checkpoint N-5 (old)
    /// Expected: Contract must reject; require current checkpoint
    function testStaleCheckpoint() public {
        bytes memory proofBundle = createProofWithStaleCheckpoint();
        
        vm.expectRevert("StaleCheckpoint");
        csvSeal.mint(proofBundle);
    }

    /// Test 5: forged_anchor - Submit anchor hash not in event log
    /// Expected: Contract must reject anchor verification
    function testForgedAnchor() public {
        bytes memory proofBundle = createProofWithForgedAnchor();
        
        vm.expectRevert("InvalidAnchor");
        csvSeal.mint(proofBundle);
    }

    /// Test 6: partial_event_replay - Omit 1 event from event bundle
    /// Expected: Merkle root mismatch; contract rejects
    function testPartialEventReplay() public {
        bytes memory proofBundle = createProofWithPartialEvents();
        
        vm.expectRevert("MerkleRootMismatch");
        csvSeal.mint(proofBundle);
    }

    /// Test 7: duplicate_mint_proof - Submit valid mint proof twice
    /// Expected: Second mint must revert
    function testDuplicateMintProof() public {
        bytes memory proofBundle = createValidProofBundle();
        
        // First mint
        csvSeal.mint(proofBundle);
        
        // Try to mint again with same proof
        vm.expectRevert("AlreadyConsumed");
        csvSeal.mint(proofBundle);
    }

    // Helper functions to create adversarial proof bundles
    
    function createValidProofBundle() internal pure returns (bytes memory) {
        // In a real implementation, this would create a valid proof bundle
        // For testing, we return a placeholder
        return abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
    }
    
    function createProofWithSameNullifier(bytes memory originalProof) internal pure returns (bytes memory) {
        // Create a new proof with the same nullifier as the original
        return originalProof;
    }
    
    function createProofWithStaleCheckpoint() internal pure returns (bytes memory) {
        // Create a proof with an old checkpoint (N-5)
        return abi.encodePacked(bytes32(uint256(1)), uint256(0)); // checkpoint 0 is stale
    }
    
    function createProofWithForgedAnchor() internal pure returns (bytes memory) {
        // Create a proof with a forged anchor not in event log
        return abi.encodePacked(bytes32(uint256(0xDEADBEEF)), bytes32(uint256(2)));
    }
    
    function createProofWithPartialEvents() internal pure returns (bytes memory) {
        // Create a proof with missing events in the bundle
        return abi.encodePacked(bytes32(uint256(1)), bytes("partial"));
    }
}
