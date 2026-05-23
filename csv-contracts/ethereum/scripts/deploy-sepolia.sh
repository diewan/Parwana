#!/bin/bash
# Ethereum Sepolia Testnet Deployment Script for CSV Contracts
#
# This script deploys the CSVLock and CSVMint contracts to Sepolia testnet
# using the csv-cli or direct Rust invocation.
#
# Prerequisites:
#   - Sepolia ETH in deployer wallet (get from sepoliafaucet.com)
#   - RPC_URL set to Sepolia endpoint (Infura/Alchemy)
#   - PRIVATE_KEY set to deployer private key (with 0x prefix)
#
# Usage:
#   export RPC_URL="https://sepolia.infura.io/v3/YOUR_KEY"
#   export PRIVATE_KEY="0x..."
#   ./deploy-sepolia.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  CSV Protocol - Sepolia Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check prerequisites
check_prereq() {
    if [ -z "$1" ]; then
        echo -e "${RED}Error: $2 is not set${NC}"
        echo -e "${YELLOW}Please set it with: export $2=...${NC}"
        exit 1
    fi
}

check_prereq "$RPC_URL" "RPC_URL"
check_prereq "$PRIVATE_KEY" "PRIVATE_KEY"

# Validate private key format
if [[ ! $PRIVATE_KEY =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo -e "${RED}Error: PRIVATE_KEY must be 66 characters (0x + 64 hex)${NC}"
    echo -e "${YELLOW}Format: 0x1234...${NC}"
    exit 1
fi

echo -e "${BLUE}Configuration:${NC}"
echo -e "  RPC URL: ${RPC_URL:0:30}..."
echo -e "  Deployer: ${PRIVATE_KEY:0:10}...${PRIVATE_KEY: -8}"
echo ""

# Check if csv-cli is available
if command -v csv &> /dev/null; then
    CLI_CMD="csv"
elif [ -f "../../csv-cli/target/release/csv" ]; then
    CLI_CMD="../../csv-cli/target/release/csv"
elif [ -f "../../csv-cli/target/debug/csv" ]; then
    CLI_CMD="../../csv-cli/target/debug/csv"
else
    echo -e "${YELLOW}csv-cli not found in PATH, will use cargo run${NC}"
    CLI_CMD="cargo run -p csv-cli --"
fi

echo -e "${BLUE}Using CLI: ${CLI_CMD}${NC}"
echo ""

# Function to deploy contract
deploy_contract() {
    local contract_name=$1
    local contract_type=$2
    
    echo -e "${YELLOW}Deploying ${contract_name}...${NC}"
    
    if [ "$CLI_CMD" = "cargo run -p csv-cli --" ]; then
        # Use cargo run
        DEPLOY_OUTPUT=$($CLI_CMD chain deploy \
            --chain ethereum \
            --network sepolia \
            --contract-type "$contract_type" \
            2>&1) || true
    else
        # Use binary directly
        DEPLOY_OUTPUT=$($CLI_CMD chain deploy \
            --chain ethereum \
            --network sepolia \
            --contract-type "$contract_type" \
            2>&1) || true
    fi
    
    echo "$DEPLOY_OUTPUT"
    
    # Extract contract address from output
    CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
    TX_HASH=$(echo "$DEPLOY_OUTPUT" | grep -oE '0x[0-9a-fA-F]{64}' | tail -1)
    
    if [ -n "$CONTRACT_ADDRESS" ]; then
        echo -e "${GREEN}✓ ${contract_name} deployed!${NC}"
        echo -e "  Address: ${CONTRACT_ADDRESS}"
        [ -n "$TX_HASH" ] && echo -e "  TX Hash: ${TX_HASH}"
        return 0
    else
        echo -e "${RED}✗ ${contract_name} deployment failed${NC}"
        return 1
    fi
}

# Deploy CSVLock
echo -e "${BLUE}Step 1: Deploy CSVLock Contract${NC}"
echo "----------------------------------------"
if deploy_contract "CSVLock" "lock"; then
    CSVLOCK_ADDR=$CONTRACT_ADDRESS
    CSVLOCK_TX=$TX_HASH
else
    echo -e "${RED}CSVLock deployment failed. Exiting.${NC}"
    exit 1
fi

echo ""

# Deploy CSVMint
echo -e "${BLUE}Step 2: Deploy CSVMint Contract${NC}"
echo "----------------------------------------"
if deploy_contract "CSVMint" "mint"; then
    CSVMINT_ADDR=$CONTRACT_ADDRESS
    CSVMINT_TX=$TX_HASH
else
    echo -e "${YELLOW}Warning: CSVMint deployment failed. Continuing...${NC}"
    CSVMINT_ADDR=""
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Deployed Contracts:${NC}"
echo -e "  CSVLock:  ${CSVLOCK_ADDR}"
[ -n "$CSVMINT_ADDR" ] && echo -e "  CSVMint:  ${CSVMINT_ADDR}"
echo ""
echo -e "${BLUE}View on Etherscan:${NC}"
echo -e "  CSVLock:  https://sepolia.etherscan.io/address/${CSVLOCK_ADDR}"
[ -n "$CSVMINT_ADDR" ] && echo -e "  CSVMint:  https://sepolia.etherscan.io/address/${CSVMINT_ADDR}"
echo ""
echo -e "${BLUE}Update your config:${NC}"
echo -e "  csv config set ethereum.contract.lock ${CSVLOCK_ADDR}"
[ -n "$CSVMINT_ADDR" ] && echo -e "  csv config set ethereum.contract.mint ${CSVMINT_ADDR}"
echo ""

# Save deployment info
DEPLOY_FILE="deploy-output-$(date +%Y%m%d-%H%M%S).json"
cat > "$DEPLOY_FILE" << EOF
{
  "network": "sepolia",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "contracts": {
    "csvlock": {
      "address": "${CSVLOCK_ADDR}",
      "tx_hash": "${CSVLOCK_TX}"
    }$(if [ -n "$CSVMINT_ADDR" ]; then echo ","; else echo ""; fi)
    $(if [ -n "$CSVMINT_ADDR" ]; then echo "    \"csvmint\": {"; echo "      \"address\": \"${CSVMINT_ADDR}\","; echo "      \"tx_hash\": \"${CSVMINT_TX}\"; echo "    }"; fi)
  },
  "rpc_url": "${RPC_URL:0:30}...",
  "deployer": "${PRIVATE_KEY:0:10}...${PRIVATE_KEY: -8}"
}
EOF

echo -e "${GREEN}Deployment info saved to: ${DEPLOY_FILE}${NC}"
