#!/usr/bin/env bash
# Deploy CSV Seal contracts on Sui Testnet
# Usage: ./deploy.sh [network] [sui-client-path]
#   network: testnet (default), devnet, mainnet
#   sui-client-path: path to sui binary (default: sui)

# To deploy with csv-cli wallet these steps are needed,
#  to convert and import the private key from csv-cli into sui client:
# sui keytool convert <csv-cli SUI PRIVATE KEY>
# sui keytool import "<BECH32 PRIVATE KEY FROM ABOVE>" ed25519
# sui client switch --address <csv-cli SUI ADDRESS>
# csv contract deploy sui --account <csv-cli SUI ADDRESS>

set -euo pipefail

NETWORK="${1:-testnet}"
SUI="${2:-sui}"

echo "=== Sui ${NETWORK} Deployment ==="
echo ""

# Check dependencies
if ! command -v "$SUI" &>/dev/null; then
    echo "ERROR: sui client not found. Install with: cargo install --git https://github.com/MystenLabs/sui.git --bin sui"
    exit 1
fi

cd "$(dirname "$0")/.."

# Initialize variables
PACKAGE_ID=""

# Check if sui config exists
SUI_CONFIG_DIR="${SUI_CONFIG_DIR:-$HOME/.sui}"
if [ ! -f "$SUI_CONFIG_DIR/client.yaml" ]; then
    echo "ERROR: Sui client not configured. Please run:"
    echo "  $SUI client new-address ed25519"
    echo "  $SUI client switch --address <your-address>"
    echo "Or set SUI_CONFIG_DIR to your sui config directory."
    exit 1
fi

# Handle csv-cli wallet if specified
if [ -n "${CSV_SUI_PRIVATE_KEY:-}" ]; then
    echo "Using csv-cli wallet for deployment..."
    
    # First check if address already exists in Sui client
    set +e
    ADDRESS_CHECK=$("$SUI" client addresses 2>&1 | grep "$CSV_SUI_ADDRESS")
    set -e
    
    if [ -n "$ADDRESS_CHECK" ]; then
        echo "Address already exists in Sui client, switching to it..."
    else
        # Address not found, need to import the key
        echo "Address not found in Sui client, importing key..."
        # Create temp keypair file
        KEYPAIR_FILE=$(mktemp)
        echo "{\"privateKey\": \"$CSV_SUI_PRIVATE_KEY\", \"scheme\": \"ed25519\"}" > "$KEYPAIR_FILE"
        echo "Created keypair file: $KEYPAIR_FILE"
        
        # Try to add address using keypair file (modern Sui CLI uses new-address)
        set +e
        IMPORT_OUTPUT=$("$SUI" client new-address --keypair-file "$KEYPAIR_FILE" --alias csv-deploy 2>&1)
        IMPORT_EXIT=$?
        set -e
        
        rm "$KEYPAIR_FILE"
        echo "Import output: $IMPORT_OUTPUT"
        
        if [ $IMPORT_EXIT -ne 0 ]; then
            # Check if it's because address already exists
            if echo "$IMPORT_OUTPUT" | grep -qi "already\|exists"; then
                echo "Key already imported, continuing..."
            else
                echo "Failed to import key: $IMPORT_OUTPUT"
                echo "Please manually import the key first:"
                echo "  sui keytool convert $CSV_SUI_PRIVATE_KEY"
                echo "  sui keytool import '<bech32-output>' ed25519"
                exit 1
            fi
        fi
    fi
    
    # Switch to the address
    set +e
    SWITCH_OUTPUT=$("$SUI" client switch --address "$CSV_SUI_ADDRESS" 2>&1)
    SWITCH_EXIT=$?
    set -e
    
    if [ $SWITCH_EXIT -ne 0 ]; then
        if echo "$SWITCH_OUTPUT" | grep -qi "already active\|same"; then
            echo "Address already active, continuing..."
        else
            echo "Failed to switch address: $SWITCH_OUTPUT"
            exit 1
        fi
    fi
    echo "Using csv-cli wallet: $CSV_SUI_ADDRESS"
else
    echo "Using Sui CLI active wallet"
fi

# Get active address
echo "Active wallet:"
"$SUI" client active-address 2>/dev/null || {
    echo "No active wallet. Run: $SUI client new-address ed25519"
    exit 1
}

echo ""

# Check balance
echo "Wallet balance:"
"$SUI" client gas 2>/dev/null | head -5 || echo "Unable to fetch gas (may need faucet)"
echo ""

# Build the package
echo "Building Move package..."
"$SUI" move build --path contracts 2>&1 | tail -5
echo ""

# Publish to testnet
echo "Publishing to ${NETWORK}..."

# Check if already published - offer to upgrade or use --with-unpublished-dependencies
if [ -f "contracts/Published.toml" ] && grep -q "\[published.${NETWORK}\]" "contracts/Published.toml" 2>/dev/null; then
    echo "Package already published to ${NETWORK}. Options:"
    echo "  1. Upgrade existing package (keeps same Package ID)"
    echo "  2. Force fresh publish (removes publication tracking, creates new Package ID)"
    echo ""
    # Default to upgrade for safety
    echo "Upgrading existing package..."
    PUBLISH_CMD="upgrade"
else
    PUBLISH_CMD="publish"
fi

set +e
if [ "$PUBLISH_CMD" = "upgrade" ]; then
    PUBLISH_OUTPUT=$("$SUI" client upgrade contracts \
        --gas-budget 500000000 \
        --json 2>&1)
else
    PUBLISH_OUTPUT=$("$SUI" client publish contracts \
        --gas-budget 500000000 \
        --json 2>&1)
fi
PUBLISH_EXIT=$?
set -e

echo "$PUBLISH_OUTPUT" > "scripts/deploy-output-${NETWORK}.json"

# Check if publish succeeded
if [ $PUBLISH_EXIT -ne 0 ]; then
    # Check if it's an authorization error (not owner of upgrade capability)
    # Match: "was not signed by" or "not owned by" or "correct sender" or "not signed"
    if echo "$PUBLISH_OUTPUT" | grep -qiE "(was not signed|not signed by|not owned by|correct sender)"; then
        echo ""
        echo "============================================================"
        echo "UPGRADE FAILED: Only the original publisher can upgrade this package."
        echo ""
        echo "The package was published by a different address."
        echo "Options:"
        echo ""
        echo "1. USE EXISTING PACKAGE (recommended for testing)"
        echo "   The package is already deployed and functional."
        echo "   Package ID: $(grep 'published-at' contracts/Published.toml | head -1 | cut -d'"' -f2)"
        echo ""
        echo "2. FORCE FRESH PUBLISH (creates new package ID)"
        echo "   rm contracts/Published.toml"
        echo "   csv contract deploy sui"
        echo ""
        echo "3. USE ORIGINAL PUBLISHER"
        echo "   Import the original publisher's key and deploy with that address"
        echo "============================================================"
        echo ""
        # For now, extract and use the existing package ID
        if [ -f "contracts/Published.toml" ]; then
            EXISTING_PACKAGE=$(grep 'published-at' contracts/Published.toml 2>/dev/null | head -1 | cut -d'"' -f2)
            if [ -n "$EXISTING_PACKAGE" ]; then
                echo "Using existing published package: $EXISTING_PACKAGE"
                PACKAGE_ID="$EXISTING_PACKAGE"
                # Skip registry init - we can't upgrade anyway
                echo ""
                echo "=== DEPLOYMENT SUMMARY ==="
                echo "Package ID: ${PACKAGE_ID}"
                echo "Network: ${NETWORK}"
                echo "Module: csv_seal::csv_seal"
                echo "Status: Already published (cannot upgrade - different owner)"
                echo "=========================="
                echo ""
                echo "The package is already deployed and can be used."
                echo "To deploy a fresh instance: rm contracts/Published.toml"
                exit 0
            fi
        fi
    else
        echo "ERROR: Publish command failed with exit code $PUBLISH_EXIT"
        echo ""
        echo "Raw output:"
        echo "$PUBLISH_OUTPUT"
        exit 1
    fi
fi

# Extract package ID from output (if not already set from fallback)
if [ -z "$PACKAGE_ID" ]; then
    # Filter out log lines (starting with timestamp) to get clean JSON
    CLEAN_JSON=$(echo "$PUBLISH_OUTPUT" | grep -v '^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T' 2>/dev/null || echo "$PUBLISH_OUTPUT")
    PACKAGE_ID=$(echo "$CLEAN_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for event in data.get('events', []):
        if event.get('type') == 'published':
            print(event['packageId'])
            sys.exit(0)
    # Fallback: parse from objectChanges
    for change in data.get('objectChanges', []):
        if change.get('type') == 'published':
            print(change.get('packageId', ''))
            sys.exit(0)
except json.JSONDecodeError as e:
    sys.stderr.write(f'JSON parse error: {e}\\n')
print('')
" 2>/dev/null || echo "")
fi

if [ -z "$PACKAGE_ID" ]; then
    echo "WARNING: Could not extract package ID from output."
    echo "Check scripts/deploy-output-${NETWORK}.json for the full response."
    echo "Look for 'packageId' in the output."
    exit 1
fi

echo ""
echo "=== DEPLOYMENT SUMMARY ==="
echo "Package ID: ${PACKAGE_ID}"
echo "Network: ${NETWORK}"
echo "Module: csv_seal::csv_seal"
echo "=========================="
echo ""
echo "Next steps:"
echo "1. Update Move.toml: csv_seal = \"${PACKAGE_ID}\""
echo "2. Initialize LockRegistry:"
echo "   sui client call --package ${PACKAGE_ID} --module csv_seal --function create_registry --gas-budget 10000000"
echo ""

# Initialize the LockRegistry
echo "Initializing LockRegistry..."
"$SUI" client call \
    --package "$PACKAGE_ID" \
    --module csv_seal \
    --function create_registry \
    --gas-budget 10000000 \
    --json 2>&1 | tee "scripts/registry-init-${NETWORK}.json" | tail -3

echo ""
echo "Deployment complete!"
