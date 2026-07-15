#!/bin/bash
# CSV CLI Quick Start Script
# This script demonstrates a complete workflow on testnet
# Interactive mode: You can skip steps you've already completed

set -e

# Add csv binary to PATH if not already available
if ! command -v csv &> /dev/null; then
    # Check debug build first, then release build
    if [ -f "../../target/debug/csv" ]; then
        export PATH="../../target/debug:$PATH"
        echo "Using csv from: ../../target/debug/csv"
    elif [ -f "../../target/release/csv" ]; then
        export PATH="../../target/release:$PATH"
        echo "Using csv from: ../../target/release/csv"
    else
        echo "ERROR: csv binary not found in ../../target/debug or ../../target/release"
        echo "Please build the CLI first: cargo build -p csv-cli --release"
        exit 1
    fi
fi

# Helper function for interactive prompts
prompt_step() {
    local step_name="$1"
    local description="$2"
    local command="$3"
    
    echo ""
    echo "=========================================="
    echo "Step: $step_name"
    echo "=========================================="
    echo "Description: $description"
    echo ""
    echo "Command: $command"
    echo ""
    read -p "Run this step? (y/n/s to skip all remaining) > " choice
    case "$choice" in 
        y|Y ) 
            echo "Running..."
            eval "$command"
            ;;
        n|N ) 
            echo "Skipping..."
            ;;
        s|S ) 
            echo "Skipping all remaining steps..."
            export SKIP_ALL=true
            ;;
        * ) 
            echo "Invalid choice. Skipping..."
            ;;
    esac
}

echo "=============================================="
echo "  Parwana CLI - Quick Start"
echo "=============================================="
echo ""
echo "This tutorial will guide you through the basic CSV CLI workflow."
echo "You can choose to run or skip each step as needed."
echo ""

if [ -z "$SKIP_ALL" ]; then
    prompt_step "List Available Chains" "Shows all supported blockchain networks" "csv chain list"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Initialize Wallet" "Creates a new wallet with test network configuration" "csv wallet init --network test --words 12"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Generate Bitcoin Address" "Derives a Bitcoin testnet address from the wallet" "csv wallet generate --chain bitcoin"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Generate Ethereum Address" "Derives an Ethereum testnet address from the wallet" "csv wallet generate --chain ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "List Wallet Addresses" "Shows all wallet addresses across supported chains" "csv wallet list"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Show Ethereum Funding Address" "Prints the derived Ethereum address to fund on testnet" "csv wallet address ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Scan Bitcoin UTXOs" "Scans derived Bitcoin addresses with the configured gap limit" "csv wallet scan bitcoin --gap-limit 20 || echo '  (UTXO scan needs a reachable Bitcoin RPC/API)'"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Wallet Balance" "Queries the runtime-backed wallet balance for Ethereum" "csv wallet balance --chain ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Chain Status" "Shows Ethereum chain configuration" "csv chain status ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Chain Readiness" "Checks signer and contract readiness for Ethereum" "csv chain readiness ethereum --json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Show Chain Capabilities" "Prints the chain capability matrix" "csv chain capabilities --json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Runtime Health" "Shows health status of runtime components (optional)" "csv runtime health || echo '  (No runtime active - health checks appear after starting transfers)'"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Trust Package" "Verifies trust package status for proof verification (optional)" "csv trust status || echo '  (No trust package - for testing this is OK, for production contact Parwana team)'"
fi

echo "=============================================="
echo "  Quick Start Complete"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Fund your wallets from testnet faucets"
echo "  2. Confirm balances: csv wallet balance --chain ethereum"
echo "  3. Create a Sanad: csv sanad create --chain ethereum --value 1000000000000000000"
echo "     → Copy the 'Sanad ID' from the output (line: 'Sanad ID')"
echo "  4. Query canonical state: csv sanad state --chain ethereum <SANAD_ID>"
echo "  5. Generate a proof: csv proof generate --chain ethereum <SANAD_ID> -o proof.cbor"
echo "     → Replace <SANAD_ID> with the value from step 3"
echo "  6. Verify the proof: csv proof verify --chain ethereum --proof proof.cbor"
echo "  7. Materialize cross-chain: csv cross-chain materialize --from ethereum --to sui --sanad-id <SANAD_ID> --dest-owner <DEST_OWNER>"
echo "     → Replace <SANAD_ID> with the value from step 3"
echo "     → Replace <DEST_OWNER> with your destination chain address (run: csv wallet list)"
echo "  8. Inspect lifecycle trace: csv sanad trace --chain ethereum <SANAD_ID>"
echo "  9. Replay attempt: repeat step 7; it must fail closed as a replay attempt"
echo "  10. Malformed proof attempt: corrupt proof.cbor and rerun step 6; it must fail closed"
echo ""
echo "Parameter Extraction Guide:"
echo "  - Sanad ID: Found in output of 'csv sanad create' (line: 'Sanad ID')"
echo "  - Dest Owner: Found in output of 'csv wallet list' (look for destination chain address)"
echo "  - Chain names: Run 'csv chain list' to see all supported chains"
echo ""
echo "About Trust Packages:"
echo "  - For TESTING: You can skip trust package setup (current setup)"
echo "  - For PRODUCTION: Contact Parwana team for official trust packages"
echo "  - See trust-management.sh for detailed trust package operations"
echo ""
