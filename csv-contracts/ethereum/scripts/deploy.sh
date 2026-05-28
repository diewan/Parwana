#!/bin/bash
# Deployment Script for CSV Contracts on Sepolia
#
# This script deploys the CSVSeal contract (merged lock + mint) to Sepolia testnet
# and updates the deployment manifest and chain configuration.
#
# Prerequisites:
# - Foundry installed (https://getfoundry.sh/)
# - Sepolia RPC URL set in SEPOLIA_RPC_URL environment variable
# - Deployer private key set in DEPLOYER_KEY environment variable
# - Etherscan API key set in ETHERSCAN_API_KEY (for contract verification)
# - Sufficient Sepolia ETH for gas fees
#
# Usage:
#   ./deploy.sh
#
# Environment variables:
#   SEPOLIA_RPC_URL - Sepolia RPC endpoint URL
#   DEPLOYER_KEY - Private key of deployer account (without 0x prefix)
#   ETHERSCAN_API_KEY - Etherscan API key for contract verification (optional)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== CSV Protocol Contract Deployment Script ===${NC}"
echo ""

# Load .env file if it exists
if [ -f "../.env" ]; then
    echo "Loading environment variables from .env..."
    export $(cat ../.env | grep -v '^#' | xargs)
fi

# Check prerequisites
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Foundry not found. Please install Foundry from https://getfoundry.sh/${NC}"
    exit 1
fi

if [ -z "$SEPOLIA_RPC_URL" ]; then
    echo -e "${RED}Error: SEPOLIA_RPC_URL environment variable not set${NC}"
    echo "Example: export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID"
    exit 1
fi

if [ -z "$DEPLOYER_KEY" ]; then
    echo -e "${RED}Error: DEPLOYER_KEY environment variable not set${NC}"
    echo "Example: export DEPLOYER_KEY=your_private_key_without_0x_prefix"
    exit 1
fi

# Get deployer address
DEPLOYER_ADDRESS=$(cast wallet address --private-key $DEPLOYER_KEY)
echo -e "${YELLOW}Deployer address: ${DEPLOYER_ADDRESS}${NC}"

# Check balance
BALANCE=$(cast balance $DEPLOYER_ADDRESS --rpc-url $SEPOLIA_RPC_URL)
echo -e "${YELLOW}Deployer balance: ${BALANCE} ETH${NC}"

if [ "$BALANCE" = "0" ]; then
    echo -e "${RED}Error: Insufficient balance. Please fund your account with Sepolia ETH${NC}"
    echo "Get Sepolia ETH from: https://sepoliafaucet.com/"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Building contracts ===${NC}"
cd ../contracts
forge install foundry-rs/forge-std
forge build --sizes

echo ""
echo -e "${GREEN}=== Deploying contracts to Sepolia ===${NC}"

# Deploy contracts
forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL \
    --private-key $DEPLOYER_KEY \
    --broadcast \
    --verify \
    -vvv

echo ""
echo -e "${GREEN}=== Extracting deployment information ===${NC}"

# Parse deployment addresses from broadcast output (we're inside contracts/ dir)
BROADCAST_DIR="broadcast/Deploy.s.sol/11155111"
RUN_FILE="$BROADCAST_DIR/run-latest.json"

if [ ! -f "$RUN_FILE" ]; then
    echo -e "${RED}Error: Deployment run file not found at $RUN_FILE${NC}"
    exit 1
fi

# Extract contract address and deployment info
SEAL_ADDRESS=$(jq -r '[.transactions[] | select(.contractName == "CSVSeal") | .contractAddress] | first' $RUN_FILE)
DEPLOYMENT_TX=$(jq -r '[.transactions[] | select(.transactionType == "CREATE") | .hash] | first' $RUN_FILE)
BLOCK_NUMBER_HEX=$(jq -r '[.receipts[] | .blockNumber] | first' $RUN_FILE)
BLOCK_NUMBER=$(printf "%d" $BLOCK_NUMBER_HEX)

echo -e "${YELLOW}CSVSeal address: ${SEAL_ADDRESS}${NC}"
echo -e "${YELLOW}Deployment TX: ${DEPLOYMENT_TX}${NC}"
echo -e "${YELLOW}Block number: ${BLOCK_NUMBER}${NC}"

cd ..

echo ""
echo -e "${GREEN}=== Updating deployment manifest ===${NC}"

# Update deployment-manifest.json (relative to csv-contracts/ethereum/)
MANIFEST="../../../deployments/deployment-manifest.json"
jq --arg seal "$SEAL_ADDRESS" \
   --arg tx "$DEPLOYMENT_TX" \
   --arg block "$BLOCK_NUMBER" \
   --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
   '
   (.deployments.ethereum.contracts[] | select(.name == "CSVSeal") | .address) = $seal |
   (.deployments.ethereum.contracts[] | select(.name == "CSVSeal") | .deployment_tx) = $tx |
   (.deployments.ethereum.contracts[] | select(.name == "CSVSeal") | .block_number) = $block |
   (.deployments.ethereum.contracts[] | select(.name == "CSVSeal") | .constructor_args.verifier) = "" |
   .deployments.ethereum.deployment_block = $block |
   .deployments.ethereum.deployment_timestamp = $timestamp |
   .deployments.ethereum.verified = true
   ' "$MANIFEST" > "${MANIFEST}.tmp" && mv "${MANIFEST}.tmp" "$MANIFEST"
echo "Deployment manifest updated successfully!"

# Update chains/ethereum.toml (relative to csv-contracts/ethereum/)
CHAINS_CONFIG="../../../chains/ethereum.toml"
if [ -f "$CHAINS_CONFIG" ]; then
    sed -i "s/contract_address = \".*\"/contract_address = \"$SEAL_ADDRESS\"/" "$CHAINS_CONFIG"
    echo "chains/ethereum.toml updated successfully!"
fi

echo -e "${YELLOW}CSVSeal address: ${SEAL_ADDRESS}${NC}"
echo -e "${YELLOW}Deployment TX: ${DEPLOYMENT_TX}${NC}"
echo -e "${YELLOW}Block number: ${BLOCK_NUMBER}${NC}"

echo ""
echo -e "${GREEN}=== Deployment completed successfully! ===${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Verify contract on Etherscan: https://sepolia.etherscan.io/address/$SEAL_ADDRESS"
echo "2. Update bytecode_hash in deployment-manifest.json using a tool like `cast hash` or `forge inspect` to compute the deployed bytecode hash"
echo "3. Set verifier address in CSVSeal constructor args if needed"
echo "4. Mark contract as verified in deployment-manifest.json"
