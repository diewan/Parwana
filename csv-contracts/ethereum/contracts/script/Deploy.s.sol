// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CSVSeal.sol";

/// @title Deploy — Deploy the thin-registry CSVSeal on Sepolia testnet (TRM-ETH-DEPLOY-001)
/// @notice Deploys the redesigned, verifier-attested CSVSeal with an initial 1-of-1 verifier
///         set and NO proof root (RFC-0012 §9.3 ETH fast-track). The former trusted-root mint
///         precondition is gone — this script installs no root, state root, or Merkle gate.
/// @dev Run with:
///        forge script script/Deploy.s.sol \
///          --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --slow -vvv
///      The verifier defaults to the deployer; override with VERIFIER_ADDRESS to seed a
///      dedicated signer. Rotation to M-of-N later needs no ABI change (timelocked governance).
contract Deploy is Script {
    /// @notice Expected on-chain protocol version. MUST match `CSVSeal.VERSION` and the
    ///         regenerated adapter binding (TRM-ETH-BIND-001). A mismatch aborts the deploy.
    uint256 public constant EXPECTED_VERSION = 6;

    error VersionMismatch(uint256 expected, uint256 actual);
    error VerifierSetNotSeeded();
    error ThresholdNotOneOfOne(uint256 threshold);
    error VerifierNotAuthorized(address verifier);
    error RegistryNotEmpty();

    function run() external returns (address sealAddr) {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);

        // Verifier defaults to the deployer; override for a dedicated signer set.
        address verifier = vm.envOr("VERIFIER_ADDRESS", deployer);

        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance);
        console.log("Initial verifier (1-of-1):", verifier);

        vm.startBroadcast(deployerKey);

        // Deploy the thin-registry CSVSeal. The constructor seeds { verifier } with threshold = 1
        // and installs NO proof root, state root, or Merkle precondition.
        CSVSeal seal = new CSVSeal(verifier);
        console.log("CSVSeal deployed at:", address(seal));

        vm.stopBroadcast();

        // ==================== Read-back sanity checks (acceptance criterion #4) ====================
        // Fail the deploy loudly if the on-chain state is not exactly the intended thin-registry
        // seed: version parity, a 1-of-1 verifier set, and an empty replay registry.

        uint256 deployedVersion = seal.VERSION();
        if (deployedVersion != EXPECTED_VERSION) {
            revert VersionMismatch(EXPECTED_VERSION, deployedVersion);
        }

        if (seal.verifier_count() != 1) revert VerifierSetNotSeeded();
        if (seal.threshold() != 1) revert ThresholdNotOneOfOne(seal.threshold());
        if (!seal.is_verifier(verifier)) revert VerifierNotAuthorized(verifier);
        if (seal.verifiers(0) != verifier) revert VerifierNotAuthorized(verifier);

        // Empty-registry probe: a fresh deploy must have consumed no replay keys. Probe a
        // deterministic non-zero id; on a virgin contract every registry lookup is false.
        bytes32 probe = keccak256(abi.encodePacked("csv.deploy.probe", address(seal)));
        if (
            seal.is_sanad_minted(probe) ||
            seal.is_nullifier_registered(probe) ||
            seal.is_lock_event_recorded(probe) ||
            seal.is_commitment_anchored(probe) ||
            seal.is_seal_consumed(probe)
        ) {
            revert RegistryNotEmpty();
        }

        // Output for CI / deployment-manifest parsing.
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("CSVSeal:", address(seal));
        console.log("VERSION:", deployedVersion);
        console.log("Owner:", seal.owner());
        console.log("Verifier count:", seal.verifier_count());
        console.log("Threshold (M-of-N):", seal.threshold());
        console.log("Network: Sepolia (chainId 11155111)");
        console.log("Thin registry: verifier-attested mint, no proof root, empty registry");
        console.log("==========================\n");

        sealAddr = address(seal);
    }
}
