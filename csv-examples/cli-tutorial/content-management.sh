#!/bin/bash
# CSV CLI Content Management Demo
# Demonstrates content tree creation, proofs, and selective disclosure

set -e

echo "=============================================="
echo "  CSV Protocol CLI - Content Management Demo"
echo "=============================================="
echo ""

# Create sample data
echo "Creating sample content data..."
cat > /tmp/content-leaves.txt << 'EOF'
{"type": "sanad", "id": "0xabcdef1234567890", "value": "1 ETH"}
{"type": "metadata", "created": "2024-01-15", "author": "Alice"}
{"type": "claim", "predicate": "authentic", "description": "Verified on Ethereum Sepolia"}
EOF

echo "Sample data created with 3 leaves"
echo ""

# Create content tree
echo "Step 1: Creating content tree..."
csv content create --input /tmp/content-leaves.txt --output /tmp/content-tree.json
echo ""

# Show tree details
echo "Step 2: Verifying content tree..."
csv content verify --tree /tmp/content-tree.json
echo ""

# Generate proof for leaf 0
echo "Step 3: Generating Merkle proof for leaf 0..."
csv content prove --tree /tmp/content-tree.json --index 0
echo ""

# Create selective disclosure
echo "Step 4: Creating selective disclosure for leaves 0,2..."
csv content disclose --tree /tmp/content-tree.json --include 0,2
echo ""

# Add participant
echo "Step 5: Adding participant..."
csv content participants add --tree /tmp/content-tree.json --key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678 --role creator
echo ""

# Create claim
echo "Step 6: Creating content claim..."
csv content claims create --tree /tmp/content-tree.json --predicate authentic --description "Content verified on Ethereum Sepolia testnet"
echo ""

# Clean up
rm -f /tmp/content-leaves.txt /tmp/content-tree.json

echo "=============================================="
echo "  Content Management Demo Complete"
echo "=============================================="
