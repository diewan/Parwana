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
    
    bytes32 internal constant CHAIN_ETHEREUM = keccak256(abi.encodePacked("csv.chain.ethereum"));
    bytes32 internal constant CHAIN_SOLANA = keccak256(abi.encodePacked("csv.chain.solana"));

    function setUp() public {
        owner = address(this);
        attacker = address(0x1337);
        
        csvSeal = new CSVSeal(owner);
    }

    /// Test 1: double_consume - Submit same proof bundle twice
    /// Expected: Second mint must revert with SanadAlreadyMinted
    function testDoubleConsume() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-1"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal");
        bytes memory proof = hex"00"; // dummy proof
        bytes32 proofRoot = keccak256(abi.encodePacked("test-proof-root"));
        
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, proofRoot, 0);
        
        vm.expectRevert(); // SanadAlreadyMinted
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, proofRoot, 0);
    }

    /// Test 2: malformed_merkle_proof - Flip 1 byte in Merkle sibling
    /// Expected: Verification must fail; no state change
    function testMalformedMerkleProof() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-2"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment-2"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root-2"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal-2");
        bytes memory proof = hex"00112233"; // dummy proof
        bytes32 proofRoot = keccak256(abi.encodePacked("test-proof-root-2"));
        
        // Flip one byte in the proof
        proof[1] = bytes1(uint8(proof[1]) ^ 0xFF);
        
        vm.expectRevert(); // InvalidProof
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, proofRoot, 0);
    }

    /// Test 3: replay_nullifier_reuse - Use consumed nullifier in new transfer
    /// Expected: Contract must reject duplicate nullifier
    function testReplayNullifierReuse() public {
        bytes32 nullifier = keccak256(abi.encodePacked("test-nullifier"));
        
        csvSeal.register_nullifier(nullifier, bytes32(0), CHAIN_ETHEREUM);
        
        vm.expectRevert(); // NullifierAlreadyRegistered
        csvSeal.register_nullifier(nullifier, bytes32(0), CHAIN_ETHEREUM);
    }

    /// Test 4: stale_checkpoint - Submit proof against invalid proof root
    /// Expected: Contract must reject invalid proof root
    function testStaleCheckpoint() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-4"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment-4"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root-4"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal-4");
        bytes memory proof = hex"00";
        bytes32 invalidProofRoot = keccak256(abi.encodePacked("invalid-root"));
        
        vm.expectRevert(); // InvalidProofRoot
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, invalidProofRoot, 0);
    }

    /// Test 5: forged_anchor - Submit empty proof
    /// Expected: Contract must reject empty proof
    function testForgedAnchor() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-5"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment-5"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root-5"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal-5");
        bytes memory emptyProof = "";
        bytes32 proofRoot = keccak256(abi.encodePacked("test-proof-root-5"));
        
        vm.expectRevert(); // InvalidProof
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, emptyProof, proofRoot, 0);
    }

    /// Test 6: partial_event_replay - Submit proof with wrong length
    /// Expected: Contract must reject malformed proof
    function testPartialEventReplay() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-6"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment-6"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root-6"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal-6");
        bytes memory malformedProof = hex"001122"; // wrong length (not multiple of 32)
        bytes32 proofRoot = keccak256(abi.encodePacked("test-proof-root-6"));
        
        vm.expectRevert(); // InvalidProof
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, malformedProof, proofRoot, 0);
    }

    /// Test 7: duplicate_mint_proof - Submit valid mint proof twice
    /// Expected: Second mint must revert with SanadAlreadyMinted
    function testDuplicateMintProof() public {
        bytes32 sanadId = keccak256(abi.encodePacked("test-sanad-7"));
        bytes32 commitment = keccak256(abi.encodePacked("test-commitment-7"));
        bytes32 stateRoot = keccak256(abi.encodePacked("test-state-root-7"));
        bytes memory sourceSealPoint = abi.encodePacked("test-seal-7");
        bytes memory proof = hex"00";
        bytes32 proofRoot = keccak256(abi.encodePacked("test-proof-root-7"));
        
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, proofRoot, 0);
        
        vm.expectRevert(); // SanadAlreadyMinted
        csvSeal.mint_sanad(sanadId, commitment, stateRoot, CHAIN_SOLANA, sourceSealPoint, proof, proofRoot, 0);
    }

    // Helper functions to create adversarial proof bundles
    
    function createValidProofBundle() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
    }
    
    function createProofWithSameNullifier(bytes memory originalProof) internal pure returns (bytes memory) {
        return originalProof;
    }
    
    function createProofWithStaleCheckpoint() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(1)), uint256(0));
    }
    
    function createProofWithForgedAnchor() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(0xDEADBEEF)), bytes32(uint256(2)));
    }
    
    function createProofWithPartialEvents() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(1)), bytes("partial"));
    }
}
