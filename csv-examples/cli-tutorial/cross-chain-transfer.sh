#!/bin/bash
# CSV CLI Cross-Chain Transfer Demo
# Demonstrates a complete cross-chain transfer workflow
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
echo "  CSV Protocol CLI - Cross-Chain Transfer Demo"
echo "=============================================="
echo ""
echo "This tutorial demonstrates a complete cross-chain transfer workflow."
echo "Note: Actual transfer requires funded testnet wallets."
echo ""

# This script demonstrates the commands for a cross-chain transfer
# Note: Actual transfer requires funded testnet wallets

# Variables to store extracted values
SANAD_ID=""
DEST_OWNER=""

echo "Configuration:"
echo "  Sanad ID: (will be extracted after creating Sanad)"
echo "  Destination Owner: (will be extracted from wallet)"
echo ""

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Source Chain Status" "Verifies connection to Ethereum Sepolia testnet" "csv chain status --chain ethereum"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Destination Chain Status" "Verifies connection to Sui testnet" "csv chain status --chain sui"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Runtime Health" "Shows health status of runtime components" "csv runtime health"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Admission Control" "Shows admission control pressure and limits" "csv runtime admission"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Trust Package" "Verifies trust package status for proof verification" "csv trust status"
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Create a Sanad on Source Chain"
    echo "=========================================="
    echo "Description: Create a Sanad on Ethereum to transfer"
    echo ""
    echo "Command:"
    echo "  csv sanad create --chain ethereum --value 1000000000000000000"
    echo ""
    echo "Note: This creates a Sanad worth 1 ETH (in wei)"
    echo "      The output will show a 'Sanad ID' - copy this for the next step"
    echo ""
    read -p "Run this step? (y/n/s to skip all remaining) > " choice
    case "$choice" in 
        y|Y ) 
            echo "Running..."
            csv sanad create --chain ethereum --value 1000000000000000000
            echo ""
            echo "IMPORTANT: Copy the 'Sanad ID' from the output above."
            echo "You will need it for the transfer step."
            read -p "Press Enter after copying the Sanad ID > " SANAD_ID
            ;;
        n|N ) 
            echo "Skipping..."
            read -p "Enter Sanad ID manually (or press Enter to use placeholder) > " SANAD_ID
            ;;
        s|S ) 
            echo "Skipping all remaining steps..."
            export SKIP_ALL=true
            ;;
        * ) 
            echo "Invalid choice. Skipping..."
            ;;
    esac
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Get Destination Owner Address"
    echo "=========================================="
    echo "Description: Get your wallet address on the destination chain (Sui)"
    echo ""
    echo "Command:"
    echo "  csv wallet list"
    echo ""
    echo "Note: Find the Sui address in the output and copy it."
    echo "      This will be the destination owner for the transfer."
    echo ""
    read -p "Run this step? (y/n/s to skip all remaining) > " choice
    case "$choice" in 
        y|Y ) 
            echo "Running..."
            csv wallet list
            echo ""
            echo "IMPORTANT: Copy the Sui address from the output above."
            echo "You will need it as the destination owner for the transfer."
            read -p "Press Enter after copying the Sui address > " DEST_OWNER
            ;;
        n|N ) 
            echo "Skipping..."
            read -p "Enter destination owner address manually (or press Enter to use placeholder) > " DEST_OWNER
            ;;
        s|S ) 
            echo "Skipping all remaining steps..."
            export SKIP_ALL=true
            ;;
        * ) 
            echo "Invalid choice. Skipping..."
            ;;
    esac
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Initiate Cross-Chain Transfer"
    echo "=========================================="
    echo "Description: Initiates a transfer from Ethereum to Sui"
    echo ""
    echo "From: Ethereum (Sepolia)"
    echo "To: Sui (Testnet)"
    echo "Sanad ID: ${SANAD_ID:-<not set>}"
    echo "Dest Owner: ${DEST_OWNER:-<not set>}"
    echo ""
    if [ -z "$SANAD_ID" ] || [ -z "$DEST_OWNER" ]; then
        echo "ERROR: Sanad ID and Destination Owner must be set before transfer."
        echo "Please complete the previous steps to extract these values."
        echo ""
        read -p "Press Enter to exit > "
        exit 1
    fi
    echo "Command:"
    echo "  csv cross-chain transfer --from ethereum --to sui --sanad-id $SANAD_ID --dest-owner $DEST_OWNER"
    echo ""
    read -p "Run this step? (y/n/s to skip all remaining) > " choice
    case "$choice" in 
        y|Y ) 
            echo "Running..."
            csv cross-chain transfer --from ethereum --to sui --sanad-id $SANAD_ID --dest-owner $DEST_OWNER
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
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Monitor Transfer Status"
    echo "=========================================="
    echo "Description: Monitor the cross-chain transfer progress"
    echo ""
    echo "Command:"
    echo "  csv cross-chain status <TRANSFER_ID>"
    echo ""
    echo "Note: Replace <TRANSFER_ID> with the actual ID from the previous step"
    echo ""
    read -p "Press Enter to continue (or 's' to skip remaining steps) > " choice
    if [[ "$choice" == "s" || "$choice" == "S" ]]; then
        export SKIP_ALL=true
    fi
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Verify Cross-Chain Proof"
    echo "=========================================="
    echo "Description: Verifies the cross-chain proof for the transfer"
    echo ""
    echo "Command:"
    echo "  csv proof verify-cross-chain --source ethereum --dest sui proof.json"
    echo ""
    echo "Note: proof.json should be generated from the transfer"
    echo ""
    read -p "Press Enter to continue (or 's' to skip remaining steps) > " choice
    if [[ "$choice" == "s" || "$choice" == "S" ]]; then
        export SKIP_ALL=true
    fi
fi

echo "=============================================="
echo "  Cross-Chain Transfer Demo Complete"
echo "=============================================="
echo ""
echo "Full workflow:"
echo "  1. csv wallet init --network test --words 12"
echo "  2. csv sanad create --chain ethereum --value 1000000000000000000"
echo "     → Copy the 'Sanad ID' from the output"
echo "  3. csv wallet list"
echo "     → Copy the destination chain address (e.g., Sui address)"
echo "  4. csv cross-chain transfer --from ethereum --to sui --sanad-id <SANAD_ID> --dest-owner <DEST_OWNER>"
echo "  5. csv cross-chain status <TRANSFER_ID>"
echo "  6. csv proof verify-cross-chain --source ethereum --dest sui proof.json"
echo ""
echo "Parameter Extraction Guide:"
echo "  - Sanad ID: Found in the output of 'csv sanad create' (line: 'Sanad ID')"
echo "  - Dest Owner: Found in the output of 'csv wallet list' (look for destination chain address)"
echo "  - Transfer ID: Found in the output of 'csv cross-chain transfer' (line: 'Transfer ID')"
echo ""
echo "About Trust Packages:"
echo "  - For TESTING: Cross-chain transfers work without trust packages"
echo "  - For PRODUCTION: Import official trust package before transfers"
echo "  - Get trust packages from: CSV Protocol team or official repositories"
echo "  - Verify before import: csv trust verify <package.json>"
echo ""
