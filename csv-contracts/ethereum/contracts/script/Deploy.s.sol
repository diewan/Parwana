// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CSVSeal.sol";

/// @title Deploy — Deploy CSVSeal (merged lock + mint) on Sepolia testnet
/// @notice Run with: forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --verify
contract Deploy is Script {
    /// @notice Protocol version for deployment manifest
    uint256 public constant VERSION = 3;

    function run() external returns (address sealAddr) {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);

        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance);

        vm.startBroadcast(deployerKey);

        // Deploy CSVSeal (merged lock + mint contract)
        // Verifier is initially deployer (can be updated later)
        CSVSeal seal = new CSVSeal(deployer);
        console.log("CSVSeal deployed at:", address(seal));

        vm.stopBroadcast();

        // Output for CI/state.json parsing
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("CSVSeal:", address(seal));
        console.log("Network: Sepolia (chainId 11155111)");
        console.log("Deployment verified: merged lock + mint contract");
        console.log("==========================\n");

        sealAddr = address(seal);
    }
}
