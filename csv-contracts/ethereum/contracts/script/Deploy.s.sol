// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CSVLock.sol";
import "../src/CSVMint.sol";

/// @title Deploy — Deploy CSVLock and CSVMint on Sepolia testnet
/// @notice Run with: forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --verify
contract Deploy is Script {
    /// @notice Protocol version for deployment manifest
    uint256 public constant VERSION = 1;

    function run() external returns (address lockAddr, address mintAddr) {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);

        console.log("Deployer:", deployer);
        console.log("Balance:", deployer.balance);

        vm.startBroadcast(deployerKey);

        // Step 1: Deploy CSVMint first (CSVLock needs its address in constructor)
        // Verifier is initially deployer (can be updated later)
        // Lock contract is initially address(0) and will be set after CSVLock deployment
        CSVMint mint = new CSVMint(address(0), deployer);
        console.log("CSVMint deployed at:", address(mint));

        // Step 2: Deploy CSVLock with mint contract address
        CSVLock lock = new CSVLock(address(mint));
        console.log("CSVLock deployed at:", address(lock));

        // Step 3: Update CSVMint with the actual lock contract address
        mint.setLockContract(address(lock));
        console.log("CSVMint.lockContract updated to:", address(lock));

        // Step 4: Verify the wiring
        require(lock.mintContract() == address(mint), "Mint contract not set in lock");
        require(mint.lockContract() == address(lock), "Lock contract not set in mint");

        vm.stopBroadcast();

        // Generate deployment manifest
        string memory manifest = _generateManifest(address(lock), address(mint));
        vm.writeLine("deployment_manifest.json", manifest);

        // Output for CI/state.json parsing
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("CSVLock:", address(lock));
        console.log("CSVMint:", address(mint));
        console.log("Network: Sepolia (chainId 11155111)");
        console.log("Deployment verified: contracts are properly wired");
        console.log("==========================\n");

        lockAddr = address(lock);
        mintAddr = address(mint);
    }

    /// @notice Generate a deployment manifest with contract addresses and metadata
    /// @param lockAddr Address of the deployed CSVLock contract
    /// @param mintAddr Address of the deployed CSVMint contract
    /// @return Manifest string in JSON format
    function _generateManifest(address lockAddr, address mintAddr) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                '{"version":',
                vm.toString(VERSION),
                ',"timestamp":',
                vm.toString(block.timestamp),
                ',"chainId":',
                vm.toString(block.chainid),
                ',"deployer":"',
                vm.toString(msg.sender),
                '","contracts":{',
                '"CSVLock":"',
                vm.toString(lockAddr),
                '","CSVMint":"',
                vm.toString(mintAddr),
                '"}}'
            )
        );
    }
}
