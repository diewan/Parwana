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
echo "  CSV Protocol CLI - Quick Start"
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
    prompt_step "List Wallet Addresses" "Shows all wallet addresses across supported chains" "csv wallet list"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Chain Status" "Verifies connection to Ethereum testnet" "csv chain status --chain ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Runtime Health" "Shows health status of runtime components (optional)" "csv runtime health || echo '  (No runtime active - health checks appear after starting transfers)'"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Trust Package" "Verifies trust package status for proof verification (optional)" "csv trust status || echo '  (No trust package - for testing this is OK, for production contact CSV Protocol team)'"
fi

echo "=============================================="
echo "  Quick Start Complete"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Fund your wallets from testnet faucets"
echo "  2. Create a Sanad: csv sanad create --chain ethereum --value 1000000000000000000"
echo "     → Copy the 'Sanad ID' from the output (line: 'Sanad ID')"
echo "  3. Generate a proof: csv proof generate --chain ethereum <SANAD_ID> -o proof.json"
echo "     → Replace <SANAD_ID> with the value from step 2"
echo "  4. Transfer cross-chain: csv cross-chain transfer --from ethereum --to sui --sanad-id <SANAD_ID> --dest-owner <DEST_OWNER>"
echo "     → Replace <SANAD_ID> with the value from step 2"
echo "     → Replace <DEST_OWNER> with your destination chain address (run: csv wallet list)"
echo ""
echo "Parameter Extraction Guide:"
echo "  - Sanad ID: Found in output of 'csv sanad create' (line: 'Sanad ID')"
echo "  - Dest Owner: Found in output of 'csv wallet list' (look for destination chain address)"
echo "  - Chain names: Run 'csv chain list' to see all supported chains"
echo ""
echo "About Trust Packages:"
echo "  - For TESTING: You can skip trust package setup (current setup)"
echo "  - For PRODUCTION: Contact CSV Protocol team for official trust packages"
echo "  - See trust-management.sh for detailed trust package operations"
echo ""
