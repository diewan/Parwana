#!/usr/bin/env bash
# Initialize LockRegistry for CSV Seal
# Usage: ./initialize.sh [network]
#   network: devnet (default), testnet, mainnet, localnet

set -euo pipefail

NETWORK="${1:-devnet}"

echo "=== Initializing CSV Seal LockRegistry on ${NETWORK} ==="
echo ""

cd "$(dirname "$0")/.."

# Check solana CLI
if ! command -v solana &>/dev/null; then
    echo "ERROR: Solana CLI not found."
    exit 1
fi

# Get program ID from keypair or Anchor.toml
PROGRAM_ID=$(solana-keygen pubkey contracts/target/deploy/csv_seal-keypair.json 2>/dev/null || echo "")
if [ -z "$PROGRAM_ID" ]; then
    echo "ERROR: Could not get program ID from keypair"
    echo "Make sure you've deployed first: anchor deploy"
    echo "Please provide it as an argument or run deploy.sh first."
    echo "Usage: $0 [network] [program-id]"
    exit 1
fi

echo "Program ID: ${PROGRAM_ID}"
echo ""

# Set cluster
solana config set --url "$NETWORK"

# Get authority (current wallet)
AUTHORITY=$(solana address)
echo "Authority: ${AUTHORITY}"
echo ""

# Derive LockRegistry PDA
# Using solana CLI to compute the PDA
REGISTRY_PDA=$(solana address -k <(echo "[255, 108, 111, 99, 107, 95, 114, 101, 103, 105, 115, 116, 114, 121]") 2>/dev/null || echo "")

# Initialize using anchor test
echo "Initializing LockRegistry via anchor test..."
cd contracts && anchor test --provider.cluster ${NETWORK} --skip-build 2>&1 | tail -20
echo ""
echo "LockRegistry initialization attempted."
echo ""
echo "Note: The LockRegistry is also automatically created when calling lock_sanad"
echo "if it doesn't exist, thanks to Anchor's init_if_needed feature."
