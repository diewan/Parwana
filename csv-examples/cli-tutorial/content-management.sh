#!/bin/bash
# CSV CLI Content Management Demo
# Demonstrates content tree creation, proofs, and selective disclosure
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
echo "  CSV Protocol CLI - Content Management Demo"
echo "=============================================="
echo ""
echo "This tutorial demonstrates content tree operations including creation,"
echo "verification, Merkle proofs, and selective disclosure."
echo ""

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Create Sample Data" "Creates sample content leaves for the tutorial" "cat > /tmp/content-leaves.txt << 'EOF'
{\"type\": \"sanad\", \"id\": \"0xabcdef1234567890\", \"value\": \"1 ETH\"}
{\"type\": \"metadata\", \"created\": \"2024-01-15\", \"author\": \"Alice\"}
{\"type\": \"claim\", \"predicate\": \"authentic\", \"description\": \"Verified on Ethereum Sepolia\"}
EOF
    echo 'Sample data created with 3 leaves'"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Create Content Tree" "Builds a Merkle tree from the content leaves" "csv content create --input /tmp/content-leaves.txt --output /tmp/content-tree.json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Verify Content Tree" "Validates the integrity of the content tree" "csv content verify /tmp/content-tree.json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Generate Merkle Proof" "Creates a Merkle proof for leaf 0" "csv content prove /tmp/content-tree.json --index 0"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Selective Disclosure" "Creates a disclosure revealing only specific leaves (0,2)" "csv content disclose /tmp/content-tree.json --include 0,2"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Encrypt Content Tree" "Prints an encrypted envelope for the content tree" "csv content encrypt /tmp/content-tree.json --key-id 0000000000000000000000000000000000000000000000000000000000000000"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Decrypt Content Envelope" "Decrypts an encrypted envelope file with the same key ID" "csv content decrypt /tmp/encrypted-envelope.json --key-id 0000000000000000000000000000000000000000000000000000000000000000 || echo '  (Create /tmp/encrypted-envelope.json from the JSON envelope printed by encrypt first)'"
fi

if [ -z "$SKIP_ALL" ]; then
    echo ""
    echo "=========================================="
    echo "Step: Add Participant"
    echo "=========================================="
    echo "Description: Adds a participant with a specific role to the content tree"
    echo ""
    echo "Note: You need a public key for this step."
    echo "      You can:"
    echo "      1. Use your wallet's public key (run: csv wallet private-key <chain> to see the key format)"
    echo "      2. Or use the example key below for testing"
    echo ""
    echo "Command:"
    echo "  csv content participants add /tmp/content-tree.json --key <PUBLIC_KEY> --role creator"
    echo ""
    echo "Example key for testing:"
    echo "  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    echo ""
    read -p "Use example key? (y/n) > " use_example
    if [[ "$use_example" == "y" || "$use_example" == "Y" ]]; then
        PUBLIC_KEY="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    else
        read -p "Enter your public key > " PUBLIC_KEY
    fi
    echo ""
    echo "Running with key: ${PUBLIC_KEY:0:20}..."
    csv content participants add /tmp/content-tree.json --key $PUBLIC_KEY --role creator
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "List Participants" "Lists participants currently attached to the content tree" "csv content participants list /tmp/content-tree.json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Create Content Claim" "Adds a claim with a predicate to the content tree" "csv content claims create /tmp/content-tree.json --predicate authentic --description 'Content verified on Ethereum Sepolia testnet'"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "List Content Claims" "Lists claims currently attached to the content tree" "csv content claims list /tmp/content-tree.json"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "Add Attachment Reference" "Adds an attachment reference to the content tree" "csv content attach add /tmp/content-tree.json /tmp/content-leaves.txt --media-type text/plain"
fi

if [ -z "$SKIP_ALL" ]; then
    prompt_step "List Attachments" "Lists attachment references on the content tree" "csv content attach list /tmp/content-tree.json"
fi

# Clean up
if [ -z "$SKIP_ALL" ]; then
    prompt_step "Clean Up" "Removes temporary files created during the tutorial" "rm -f /tmp/content-leaves.txt /tmp/content-tree.json /tmp/encrypted-envelope.json"
fi

echo "=============================================="
echo "  Content Management Demo Complete"
echo "=============================================="
echo ""
echo "Parameter Guide:"
echo "  - Public keys: Can be obtained from 'csv wallet private-key <chain>' (shows key format)"
echo "  - Tree file: Created by 'csv content create --input <file> --output <tree.json>'"
echo "  - Leaf indices: Start from 0, correspond to line numbers in input file"
echo "  - Roles: Common roles include 'creator', 'verifier', 'viewer', 'admin'"
echo "  - Predicates: Common predicates include 'authentic', 'verified', 'signed', 'approved'"
echo ""
echo "Content tree workflow:"
echo "  1. Create input file with one leaf per line"
echo "  2. csv content create --input <file> --output <tree.json>"
echo "  3. csv content verify <tree.json>"
echo "  4. csv content prove <tree.json> --index <n>"
echo "  5. csv content disclose <tree.json> --include <indices>"
echo "  6. csv content attach|participants|claims list <tree.json>"
echo ""
