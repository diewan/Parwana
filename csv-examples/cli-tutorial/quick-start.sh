#!/bin/bash
# CSV CLI Quick Start Script
# This script demonstrates a complete workflow on testnet

set -e

echo "=============================================="
echo "  CSV Protocol CLI - Quick Start"
echo "=============================================="
echo ""

# Step 1: Check available chains
echo "Step 1: Listing available chains..."
csv chain list
echo ""

# Step 2: Initialize wallet (uncomment to run)
# echo "Step 2: Initializing wallet..."
# csv wallet init --network test --words 12
# echo ""

# Step 3: Check wallet addresses
echo "Step 3: Listing wallet addresses..."
csv wallet list
echo ""

# Step 4: Check chain status
echo "Step 4: Checking Ethereum testnet status..."
csv chain status --chain ethereum
echo ""

# Step 5: Check runtime health
echo "Step 5: Checking runtime health..."
csv runtime health
echo ""

# Step 6: Check trust package status
echo "Step 6: Checking trust package status..."
csv trust status
echo ""

echo "=============================================="
echo "  Quick Start Complete"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Fund your wallets from testnet faucets"
echo "  2. Create a Sanad: csv sanad create --chain ethereum --value 1000000000000000000"
echo "  3. Generate a proof: csv proof generate --chain ethereum <SANAD_ID> -o proof.json"
echo "  4. Transfer cross-chain: csv cross-chain transfer --from ethereum --to sui --sanad-id <SANAD_ID>"
echo ""
