#!/bin/bash
# CSV CLI Trust Management Demo
# Demonstrates trust package operations
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
echo "  CSV Protocol CLI - Trust Management Demo"
echo "=============================================="
echo ""
echo "This tutorial demonstrates trust package operations including status checks,"
echo "export, verification, and checkpoint rotation."
echo ""

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Check Trust Package Status" "Shows current trust package status and checkpoint info" "csv trust status"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Export Trust Package" "Exports the current trust package to a file" "csv trust export -o /tmp/trust-export.json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Verify Trust Package" "Verifies the integrity of the exported trust package" "csv trust verify /tmp/trust-export.json"
fi

# Clean up
if [ -z "$SKIP_ALL" ]; then
    prompt_step "Clean Up" "Removes temporary exported trust package file" "rm -f /tmp/trust-export.json"
fi

echo "=============================================="
echo "  Trust Management Demo Complete"
echo "=============================================="
echo ""
echo "Can users create these files?"
echo ""
echo "proof.json: YES - Generate with CLI:"
echo "  csv proof generate --chain <chain> <SANAD_ID> -o proof.json"
echo "  (The CLI creates cryptographic proofs from blockchain data)"
echo ""
echo "Parameter Extraction Guide:"
echo "  - <chain>: Run 'csv chain list' to see all supported chains (e.g., ethereum, bitcoin, sui)"
echo "  - <SANAD_ID>: Found in output of 'csv sanad create' (line: 'Sanad ID')"
echo "  - <height>: Block height - can be obtained from chain explorers or 'csv chain status --chain <chain>'"
echo "  - <hash>: Block hash - can be obtained from chain explorers or 'csv chain status --chain <chain>'"
echo ""
echo "trust-package.json: NO - Cannot create yourself"
echo "  - Requires multi-sig signatures from trusted authorities"
echo "  - Contains official validator sets and checkpoints"
echo "  - Must obtain from CSV Protocol team or official repositories"
echo ""
echo "Where to get a trust package:"
echo ""
echo "For TESTING/DEVELOPMENT:"
echo "  - You can skip trust package setup entirely"
echo "  - The CLI will show informational messages when no trust package is present"
echo "  - Proof verification will work with reduced security guarantees"
echo ""
echo "For PRODUCTION use:"
echo "  1. Contact the CSV Protocol team for official trust packages"
echo "  2. Download from trusted sources (official CSV Protocol repositories)"
echo "  3. Verify the package signature before importing: csv trust verify <package.json>"
echo "  4. Import: csv trust import /path/to/trust-package.json"
echo ""
echo "Trust package structure contains:"
echo "  - Genesis hash (chain identifier)"
echo "  - Trusted checkpoint (block height and hash)"
echo "  - Validator set information"
echo "  - Multi-sig signatures from trusted authorities"
echo ""
echo "To rotate to a new checkpoint:"
echo "  csv trust rotate <height> <hash>"
echo "  → <height> and <hash> can be obtained from chain explorers or 'csv chain status --chain <chain>'"
echo ""
