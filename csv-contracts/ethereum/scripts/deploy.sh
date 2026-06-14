#!/bin/bash
# Deployment Script for CSVSeal Contract
#
# Deploys CSVSeal to Ethereum and updates:
# - ~/.csv/config.toml (contract_address)
# - ~/.csv/deployment-ethereum.json (deployment manifest)
#
# Prerequisites:
# - Foundry installed
# - SEPOLIA_RPC_URL and DEPLOYER_KEY environment variables
#
# Usage:
#   ./deploy.sh [network]
#
# Networks: sepolia (default), mainnet

set -e

NETWORK="${1:-sepolia}"
CHAIN_ID="11155111"
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"

if [ "$NETWORK" = "mainnet" ]; then
    CHAIN_ID="1"
    RPC_URL="https://eth.llamarpc.com"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== CSVSeal Deployment to $NETWORK ===${NC}"

# Check prerequisites
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Foundry not found${NC}"
    exit 1
fi

if [ -z "$SEPOLIA_RPC_URL" ] && [ "$NETWORK" = "sepolia" ]; then
    export SEPOLIA_RPC_URL="$RPC_URL"
fi

if [ -z "$DEPLOYER_KEY" ]; then
    echo -e "${RED}Error: DEPLOYER_KEY not set${NC}"
    exit 1
fi

DEPLOYER_ADDRESS=$(cast wallet address --private-key $DEPLOYER_KEY)
echo -e "${YELLOW}Deployer: $DEPLOYER_ADDRESS${NC}"

# Build contracts
echo -e "${GREEN}Building contracts...${NC}"
cd "$(dirname "$0")/../contracts"

# Clean previous builds to ensure fresh compilation
echo -e "${YELLOW}Cleaning previous builds...${NC}"
forge clean
rm -rf out/ broadcast/ cache/

# Build from scratch
forge build --sizes 2>&1 | tail -5

# Deploy (NO --verify flag — verification is done separately)
echo -e "${GREEN}Deploying CSVSeal...${NC}"
forge script script/Deploy.s.sol \
    --rpc-url "$SEPOLIA_RPC_URL" \
    --private-key "$DEPLOYER_KEY" \
    --broadcast \
    --slow \
    -vvv

# Extract deployment info
BROADCAST_DIR="broadcast/Deploy.s.sol/$CHAIN_ID"
RUN_FILE="$BROADCAST_DIR/run-latest.json"

if [ ! -f "$RUN_FILE" ]; then
    # Try to find any run file
    RUN_FILE=$(ls -t "$BROADCAST_DIR"/run-*.json 2>/dev/null | head -1)
fi

if [ -z "$RUN_FILE" ] || [ ! -f "$RUN_FILE" ]; then
    echo -e "${RED}Error: No deployment run file found${NC}"
    exit 1
fi

SEAL_ADDRESS=$(jq -r '[.transactions[] | select(.contractName == "CSVSeal") | .contractAddress] | first' "$RUN_FILE")
DEPLOYMENT_TX=$(jq -r '[.transactions[] | select(.transactionType == "CREATE") | .hash] | first' "$RUN_FILE")
BLOCK_NUMBER=$(jq -r '[.receipts[] | .blockNumber] | first' "$RUN_FILE")
BLOCK_NUMBER_DEC=$(printf "%d" "$BLOCK_NUMBER" 2>/dev/null || echo "$BLOCK_NUMBER")

echo -e "${GREEN}CSVSeal deployed:${NC}"
echo -e "  Address: $SEAL_ADDRESS"
echo -e "  TX: $DEPLOYMENT_TX"
echo -e "  Block: $BLOCK_NUMBER_DEC"

# Compute bytecode hash using cast keccak (Ethereum's Keccak-256)
BYTECODE_PATH="out/CSVSeal.sol/CSVSeal.json"
BYTECODE_HASH="unknown"
ABI_HASH="unknown"
PINNED_BYTECODE_HASH="0x7227e552d193c02a3ca5f1c57bbd4e7fc5fb77fdddd3e054efd9c1ad54efa0ab"
PINNED_ABI_HASH="0x74bac11175cda72653bd80bce55b616c2d81c9fc8e9da52668235235d3f80f41"

if [ -f "$BYTECODE_PATH" ]; then
    BYTECODE=$(jq -r '.bytecode.object' "$BYTECODE_PATH")
    if [ -n "$BYTECODE" ] && [ "$BYTECODE" != "null" ]; then
        BYTECODE_HASH=$(cast keccak "$BYTECODE")
    fi
    # Compute ABI hash (hash of entire ABI JSON)
    ABI_HASH=$(cast keccak "$(cat "$BYTECODE_PATH")")
    
    # Assert against pinned constants
    echo -e "${YELLOW}Verifying hashes against pinned constants...${NC}"
    if [ "$BYTECODE_HASH" != "$PINNED_BYTECODE_HASH" ]; then
        echo -e "${RED}ERROR: Bytecode hash mismatch!${NC}"
        echo -e "  Computed: $BYTECODE_HASH"
        echo -e "  Pinned:   $PINNED_BYTECODE_HASH"
        echo -e "${RED}Deployment aborted - contract bytecode does not match pinned hash${NC}"
        exit 1
    fi
    if [ "$ABI_HASH" != "$PINNED_ABI_HASH" ]; then
        echo -e "${RED}ERROR: ABI hash mismatch!${NC}"
        echo -e "  Computed: $ABI_HASH"
        echo -e "  Pinned:   $PINNED_ABI_HASH"
        echo -e "${RED}Deployment aborted - contract ABI does not match pinned hash${NC}"
        exit 1
    fi
    echo -e "${GREEN}Hash verification passed${NC}"
fi

# Update ~/.csv/config.toml
CONFIG_FILE="$HOME/.csv/config.toml"
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${GREEN}Updating $CONFIG_FILE...${NC}"
    # Use sed to update contract_address for ethereum chain
    if command -v sed &> /dev/null; then
        # Create backup
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%s)"
        # Update contract_address
        sed -i.bak "s|contract_address = \".*\"|contract_address = \"$SEAL_ADDRESS\"|" "$CONFIG_FILE"
        rm -f "${CONFIG_FILE}.bak"
        echo -e "${GREEN}  contract_address updated${NC}"
    fi
else
    echo -e "${YELLOW}Warning: $CONFIG_FILE not found, skipping config update${NC}"
fi

# Update ~/.csv/deployment-ethereum.json
DEPLOYMENT_FILE="$HOME/.csv/deployment-ethereum.json"
DEPLOYMENT_DIR=$(dirname "$DEPLOYMENT_FILE")
mkdir -p "$DEPLOYMENT_DIR"

cat > "$DEPLOYMENT_FILE" << EOF
{
  "version": "1.0.0",
  "network": "$NETWORK",
  "chain_id": $CHAIN_ID,
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "contracts": {
    "CSVSeal": {
      "address": "$SEAL_ADDRESS",
      "deployment_tx": "$DEPLOYMENT_TX",
      "block_number": $BLOCK_NUMBER_DEC,
      "bytecode_hash": "$BYTECODE_HASH",
      "abi_hash": "$ABI_HASH",
      "verified": false,
      "constructor_args": {
        "verifier": "$DEPLOYER_ADDRESS"
      }
    }
  },
  "protocol_version": "1.0.0"
}
EOF

echo -e "${GREEN}Deployment manifest written to $DEPLOYMENT_FILE${NC}"

# Copy to repo deployments folder if it exists
REPO_DEPLOYMENTS="$(dirname "$0")/../../deployments"
if [ -d "$REPO_DEPLOYMENTS" ]; then
    mkdir -p "$REPO_DEPLOYMENTS/ethereum"
    cp "$DEPLOYMENT_FILE" "$REPO_DEPLOYMENTS/ethereum/deployment.json"
    echo -e "${GREEN}Copied to $REPO_DEPLOYMENTS/ethereum/deployment.json${NC}"
fi

echo -e "${GREEN}=== Deployment complete ===${NC}"
echo ""
echo "Next steps:"
echo "  1. Verify contract: forge verify-contract --chain-id $CHAIN_ID $SEAL_ADDRESS script/Deploy.s.sol:CSVSeal --constructor-args $(cast abi-encode 'constructor(address)' $DEPLOYER_ADDRESS) --rpc-url $SEPOLIA_RPC_URL --etherscan-api-key \"\${ETHERSCAN_API_KEY}\""
echo "  2. Update ABI hash in deployment manifest after verification"
echo "  3. Update ~/.csv/config.toml contract_address if not done automatically"
