#!/bin/bash
# CSV CLI Cross-Chain Transfer Demo
# Demonstrates a complete cross-chain transfer workflow

set -e

echo "=============================================="
echo "  CSV Protocol CLI - Cross-Chain Transfer Demo"
echo "=============================================="
echo ""

# This script demonstrates the commands for a cross-chain transfer
# Note: Actual transfer requires funded testnet wallets

SANAD_ID="${1:-0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890}"
DEST_OWNER="${2:-0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678}"

echo "Step 1: Checking source chain (Ethereum) status..."
csv chain status --chain ethereum
echo ""

echo "Step 2: Checking destination chain (Sui) status..."
csv chain status --chain sui
echo ""

echo "Step 3: Checking runtime health..."
csv runtime health
echo ""

echo "Step 4: Checking admission control..."
csv runtime admission
echo ""

echo "Step 5: Checking trust package..."
csv trust status
echo ""

echo "Step 6: Initiating cross-chain transfer..."
echo "  From: Ethereum (Sepolia)"
echo "  To: Sui (Testnet)"
echo "  Sanad ID: $SANAD_ID"
echo "  Dest Owner: $DEST_OWNER"
echo ""
echo "Command:"
echo "  csv cross-chain transfer --from ethereum --to sui --sanad-id $SANAD_ID --dest-owner $DEST_OWNER"
echo ""

echo "Step 7: After transfer initiation, monitor with:"
echo "  csv cross-chain status <TRANSFER_ID>"
echo ""

echo "Step 8: Verify the proof:"
echo "  csv proof verify-cross-chain --source ethereum --dest sui proof.json"
echo ""

echo "=============================================="
echo "  Cross-Chain Transfer Demo Complete"
echo "=============================================="
echo ""
echo "Full workflow:"
echo "  1. csv wallet init --network test --words 12"
echo "  2. csv sanad create --chain ethereum --value 1000000000000000000"
echo "  3. csv proof generate --chain ethereum <SANAD_ID> -o proof.json"
echo "  4. csv cross-chain transfer --from ethereum --to sui --sanad-id <SANAD_ID> --dest-owner <OWNER>"
echo "  5. csv cross-chain status <TRANSFER_ID>"
echo "  6. csv proof verify-cross-chain --source ethereum --dest sui proof.json"
echo ""
