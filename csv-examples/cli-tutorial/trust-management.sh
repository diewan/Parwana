#!/bin/bash
# CSV CLI Trust Management Demo
# Demonstrates trust package operations

set -e

echo "=============================================="
echo "  CSV Protocol CLI - Trust Management Demo"
echo "=============================================="
echo ""

# Check current trust status
echo "Step 1: Checking current trust package status..."
csv trust status
echo ""

# Export trust package (if it exists)
echo "Step 2: Exporting trust package..."
csv trust export -o /tmp/trust-export.json
echo ""

# Verify the exported package
echo "Step 3: Verifying exported trust package..."
csv trust verify /tmp/trust-export.json
echo ""

# Clean up
rm -f /tmp/trust-export.json

echo "=============================================="
echo "  Trust Management Demo Complete"
echo "=============================================="
echo ""
echo "Note: To import a trust package from a trusted source:"
echo "  csv trust import /path/to/trust-package.json"
echo ""
echo "To rotate to a new checkpoint:"
echo "  csv trust rotate <height> <hash>"
echo ""
