#!/bin/bash
# Verification Script for CSVSeal Contract Deployment
#
# Verifies that the deployed contract matches the expected ABI and bytecode hashes.
# This script should be run after deployment to ensure contract integrity.
#
# Usage:
#   ./verify-deployment.sh <network> <contract_address>
#
# Networks: sepolia (default), mainnet

set -e

NETWORK="${1:-sepolia}"
CONTRACT_ADDRESS="${2:-}"

if [ -z "$CONTRACT_ADDRESS" ]; then
    echo "Error: Contract address required"
    echo "Usage: $0 <network> <contract_address>"
    exit 1
fi

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

echo -e "${GREEN}=== CSVSeal Deployment Verification ===${NC}"
echo -e "Network: $NETWORK"
echo -e "Contract: $CONTRACT_ADDRESS"
echo ""

# Check prerequisites
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Foundry not found${NC}"
    exit 1
fi

if [ -z "$SEPOLIA_RPC_URL" ] && [ "$NETWORK" = "sepolia" ]; then
    export SEPOLIA_RPC_URL="$RPC_URL"
fi

# Load deployment manifest
DEPLOYMENT_FILE="$HOME/.csv/deployment-ethereum.json"
if [ ! -f "$DEPLOYMENT_FILE" ]; then
    echo -e "${YELLOW}Warning: Deployment manifest not found at $DEPLOYMENT_FILE${NC}"
    echo "Verification will proceed without manifest comparison"
    EXPECTED_BYTECODE_HASH=""
    EXPECTED_ABI_HASH=""
else
    EXPECTED_BYTECODE_HASH=$(jq -r '.contracts.CSVSeal.bytecode_hash' "$DEPLOYMENT_FILE")
    EXPECTED_ABI_HASH=$(jq -r '.contracts.CSVSeal.abi_hash' "$DEPLOYMENT_FILE")
    echo -e "${GREEN}Loaded deployment manifest${NC}"
    echo -e "  Expected bytecode hash: $EXPECTED_BYTECODE_HASH"
    echo -e "  Expected ABI hash: $EXPECTED_ABI_HASH"
    echo ""
fi

# Get deployed bytecode
echo -e "${GREEN}Fetching deployed bytecode...${NC}"
DEPLOYED_BYTECODE=$(cast code "$CONTRACT_ADDRESS" --rpc-url "$RPC_URL")
if [ -z "$DEPLOYED_BYTECODE" ] || [ "$DEPLOYED_BYTECODE" = "0x" ]; then
    echo -e "${RED}Error: No bytecode found at contract address${NC}"
    exit 1
fi

# Compute deployed bytecode hash
DEPLOYED_BYTECODE_HASH=$(echo -n "$DEPLOYED_BYTECODE" | sha3sum | awk '{print "0x"$1}')
echo -e "  Deployed bytecode hash: $DEPLOYED_BYTECODE_HASH"

# Get local bytecode
echo -e "${GREEN}Building local bytecode...${NC}"
cd "$(dirname "$0")/../contracts"
forge build --sizes 2>&1 | tail -5

BYTECODE_PATH="out/CSVSeal.sol/CSVSeal.json"
if [ ! -f "$BYTECODE_PATH" ]; then
    echo -e "${RED}Error: Compiled bytecode not found${NC}"
    exit 1
fi

LOCAL_BYTECODE=$(jq -r '.bytecode.object' "$BYTECODE_PATH")
LOCAL_BYTECODE_HASH=$(echo -n "$LOCAL_BYTECODE" | sha3sum | awk '{print "0x"$1}')
echo -e "  Local bytecode hash: $LOCAL_BYTECODE_HASH"

# Compute local ABI hash
LOCAL_ABI_HASH=$(cat "$BYTECODE_PATH" | sha3sum | awk '{print "0x"$1}')
echo -e "  Local ABI hash: $LOCAL_ABI_HASH"
echo ""

# Verify bytecode hash
echo -e "${GREEN}Verifying bytecode hash...${NC}"
if [ "$DEPLOYED_BYTECODE_HASH" = "$LOCAL_BYTECODE_HASH" ]; then
    echo -e "${GREEN}✓ Bytecode hash matches local build${NC}"
else
    echo -e "${RED}✗ Bytecode hash mismatch!${NC}"
    echo -e "  Deployed: $DEPLOYED_BYTECODE_HASH"
    echo -e "  Local: $LOCAL_BYTECODE_HASH"
    exit 1
fi

# Verify against manifest if available
if [ -n "$EXPECTED_BYTECODE_HASH" ] && [ "$EXPECTED_BYTECODE_HASH" != "unknown" ]; then
    if [ "$DEPLOYED_BYTECODE_HASH" = "$EXPECTED_BYTECODE_HASH" ]; then
        echo -e "${GREEN}✓ Bytecode hash matches deployment manifest${NC}"
    else
        echo -e "${RED}✗ Bytecode hash mismatch with manifest!${NC}"
        echo -e "  Deployed: $DEPLOYED_BYTECODE_HASH"
        echo -e "  Expected: $EXPECTED_BYTECODE_HASH"
        exit 1
    fi
fi

# Verify ABI hash
echo -e "${GREEN}Verifying ABI hash...${NC}"
if [ -n "$EXPECTED_ABI_HASH" ] && [ "$EXPECTED_ABI_HASH" != "unknown" ]; then
    if [ "$LOCAL_ABI_HASH" = "$EXPECTED_ABI_HASH" ]; then
        echo -e "${GREEN}✓ ABI hash matches deployment manifest${NC}"
    else
        echo -e "${RED}✗ ABI hash mismatch with manifest!${NC}"
        echo -e "  Local: $LOCAL_ABI_HASH"
        echo -e "  Expected: $EXPECTED_ABI_HASH"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ ABI hash verification skipped (no manifest or unknown value)${NC}"
fi

# Verify contract version
echo -e "${GREEN}Verifying contract version...${NC}"
VERSION=$(cast call "$CONTRACT_ADDRESS" "VERSION()(uint256)" --rpc-url "$RPC_URL")
echo -e "  Contract version: $VERSION"
if [ "$VERSION" = "4" ]; then
    echo -e "${GREEN}✓ Contract version matches expected (4)${NC}"
else
    echo -e "${YELLOW}⚠ Contract version is $VERSION (expected 4)${NC}"
fi

# Verify chain IDs are hashed
echo -e "${GREEN}Verifying chain ID hashing...${NC}"
CHAIN_BITCOIN=$(cast call "$CONTRACT_ADDRESS" "CHAIN_BITCOIN()(bytes32)" --rpc-url "$RPC_URL")
EXPECTED_CHAIN_BITCOIN="0x$(echo -n 'csv.chain.bitcoin' | sha3sum | awk '{print $1}')"
if [ "$CHAIN_BITCOIN" = "$EXPECTED_CHAIN_BITCOIN" ]; then
    echo -e "${GREEN}✓ Chain IDs are hashed (not u8)${NC}"
else
    echo -e "${RED}✗ Chain ID hashing mismatch!${NC}"
    echo -e "  Bitcoin chain: $CHAIN_BITCOIN"
    echo -e "  Expected: $EXPECTED_CHAIN_BITCOIN"
    exit 1
fi

echo ""
echo -e "${GREEN}=== All verifications passed ===${NC}"
echo -e "${GREEN}Contract deployment is valid${NC}"
