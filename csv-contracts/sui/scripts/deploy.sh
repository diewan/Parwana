#!/usr/bin/env bash
# Deploy CSV Seal contracts on Sui Testnet
# Usage: ./deploy.sh [network] [sui-client-path]
#   network: testnet (default), devnet, mainnet
#   sui-client-path: path to sui binary (default: sui)
#
# Env:
#   CSV_SUI_PUBLISH_MODE=fresh|upgrade  Non-interactive publish choice when the
#       package is already published (skips the prompt). `fresh` resets the
#       Move.toml address to 0x0 and creates a NEW package + NEW shared Registry.
#
# On a fresh publish this records, into deployments/deployment-manifest.json and
# chains/sui-<network>.toml: package_id AND the shared Registry object id
# (RFC-0012 §9.2 destinationContract, required for mint), plus the AdminCap /
# UpgradeCap. Mint stays fail-closed until the AdminCap holder seeds the verifier
# set — the summary prints the exact add_verifier / set_threshold commands.

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

# Decide publish vs upgrade BEFORE building. A fresh publish must reset the
# package address in Move.toml back to 0x0: Sui automated address management
# treats a non-0x0 `csv_seal` address (or a lingering [published.<net>] entry)
# as "already published" and refuses to publish. That reset has to happen before
# the build so the fresh 0x0 address is what gets compiled and published.
PUBLISH_CMD="publish"
if [ -f "Published.toml" ] && grep -q "\[published.${NETWORK}\]" "Published.toml" 2>/dev/null; then
    # CSV_SUI_PUBLISH_MODE=fresh|upgrade selects non-interactively (automation/CI).
    CHOICE_MODE="${CSV_SUI_PUBLISH_MODE:-}"
    if [ -z "$CHOICE_MODE" ]; then
        echo "Package already published to ${NETWORK}. Options:"
        echo "  1. Upgrade existing package (keeps same Package ID + Registry)"
        echo "  2. Force fresh publish (new Package ID AND a new shared Registry object)"
        echo ""
        read -p "Choose option (1 or 2): " CHOICE
        if [ "$CHOICE" = "2" ]; then CHOICE_MODE="fresh"; else CHOICE_MODE="upgrade"; fi
    fi
    if [ "$CHOICE_MODE" = "fresh" ]; then
        PUBLISH_CMD="publish"
        echo "Forcing fresh publish..."
        # 1) Drop the publication entry for this environment.
        sed -i "/\[published\.${NETWORK}\]/,/^$/d" Published.toml 2>/dev/null || true
        # 2) Reset the package address so a fresh publish is allowed.
        sed -i "s/^csv_seal = \"0x[0-9a-fA-F]\{2,\}\"/csv_seal = \"0x0\"/" Move.toml
        echo "Reset Move.toml: csv_seal = 0x0 (fresh publish)"
    else
        PUBLISH_CMD="upgrade"
        echo "Upgrading existing package..."
    fi
fi

# Build the package (clean first so the reset address is embedded fresh)
echo "Building Move package..."
echo "Cleaning previous builds..."
rm -rf build/ dependencies/
"$SUI" move build 2>&1 | tail -5
echo ""

echo "Publishing to ${NETWORK} (mode: ${PUBLISH_CMD})..."

set +e
if [ "$PUBLISH_CMD" = "upgrade" ]; then
    PUBLISH_OUTPUT=$("$SUI" client upgrade \
        --gas-budget 500000000 \
        --json 2>&1)
else
    PUBLISH_OUTPUT=$("$SUI" client publish \
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
        echo "   Package ID: $(grep 'published-at' Published.toml | head -1 | cut -d'"' -f2)"
        echo ""
        echo "2. FORCE FRESH PUBLISH (creates new package ID)"
        echo "   rm Published.toml"
        echo "   csv contract deploy sui"
        echo ""
        echo "3. USE ORIGINAL PUBLISHER"
        echo "   Import the original publisher's key and deploy with that address"
        echo "============================================================"
        echo ""
        # For now, extract and use the existing package ID
        if [ -f "Published.toml" ]; then
            EXISTING_PACKAGE=$(grep 'published-at' Published.toml 2>/dev/null | head -1 | cut -d'"' -f2)
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
                echo "To deploy a fresh instance: rm Published.toml"
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

# Extract deployed identities from the publish output. Beyond the package id we
# MUST capture the shared Registry object id: it is the RFC-0012 §9.2
# `destinationContract` the mint attestation binds, it is DISTINCT from the
# package id, and the Sui adapter resolves it from the manifest
# (get_sui_registry_id) — an unrecorded Registry makes Sui mint fail closed.
REGISTRY_ID=""
ADMIN_CAP=""
UPGRADE_CAP=""
DEPLOY_TX=""
# Extract JSON portion from output (handles build warnings / ANSI codes).
CLEAN_JSON=$(echo "$PUBLISH_OUTPUT" | sed -n '/^{/,/^}/p' 2>/dev/null || echo "$PUBLISH_OUTPUT")
EXTRACT=$(echo "$CLEAN_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
pkg = registry = admin = upgrade = ''
tx = data.get('digest', '')
for c in data.get('objectChanges', []):
    t = c.get('type')
    if t == 'published':
        pkg = c.get('packageId', '')
    elif t == 'created':
        ot = c.get('objectType', '')
        if ot.endswith('::csv_seal::Registry'):
            registry = c.get('objectId', '')
        elif ot.endswith('::csv_seal::AdminCap'):
            admin = c.get('objectId', '')
        elif ot.endswith('::package::UpgradeCap'):
            upgrade = c.get('objectId', '')
print('\t'.join([pkg, registry, admin, upgrade, tx]))
" 2>/dev/null || echo "")
if [ -n "$EXTRACT" ]; then
    IFS=$'\t' read -r P_ID R_ID A_ID U_ID T_ID <<< "$EXTRACT"
    [ -z "$PACKAGE_ID" ] && PACKAGE_ID="$P_ID"
    REGISTRY_ID="$R_ID"
    ADMIN_CAP="$A_ID"
    UPGRADE_CAP="$U_ID"
    DEPLOY_TX="$T_ID"
fi

if [ -z "$PACKAGE_ID" ]; then
    echo "WARNING: Could not extract package ID from output."
    echo "Check scripts/deploy-output-${NETWORK}.json for the full response."
    echo "Look for 'packageId' in the output."
    exit 1
fi
if [ -z "$REGISTRY_ID" ]; then
    echo "WARNING: Could not extract the shared Registry object id."
    echo "Sui mint reads registry_id from the manifest and FAILS CLOSED without it."
    echo "Inspect scripts/deploy-output-${NETWORK}.json (objectChanges: type=created,"
    echo "objectType ending in ::csv_seal::Registry) and record it manually."
fi

# Update Move.toml with the deployed package ID
echo "Updating Move.toml with deployed package ID..."
if [ -f "Move.toml" ]; then
    if command -v sed &>/dev/null; then
        sed -i "s/^csv_seal = \"0x0\"/csv_seal = \"${PACKAGE_ID}\"/" Move.toml
        echo "Move.toml updated: csv_seal = ${PACKAGE_ID}"
    else
        echo "WARNING: sed not found, cannot auto-update Move.toml"
        echo "Please manually update Move.toml: csv_seal = \"${PACKAGE_ID}\""
    fi
else
    echo "WARNING: Move.toml not found"
fi

# Update ~/.csv/config.toml with the deployed package ID
CONFIG_FILE="$HOME/.csv/config.toml"
if [ -f "$CONFIG_FILE" ]; then
    echo "Updating $CONFIG_FILE..."
    # Use sed to update contract_address for sui chain
    if command -v sed &>/dev/null; then
        # Create backup
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%s)"
        # Update contract_address for sui chain
        sed -i.bak "/\[chains.sui\]/,/^\[/ s|contract_address = \".*\"|contract_address = \"${PACKAGE_ID}\"|" "$CONFIG_FILE"
        rm -f "${CONFIG_FILE}.bak"
        echo "  sui contract_address updated to ${PACKAGE_ID}"
    else
        echo "WARNING: sed not found, cannot auto-update config file"
        echo "Please manually update $CONFIG_FILE"
        echo "Set chains.sui.contract_address = ${PACKAGE_ID}"
    fi
else
    echo "WARNING: $CONFIG_FILE not found, skipping config update"
fi

# Update deployment manifest
echo "Updating deployment manifest..."
# Calculate manifest path from current directory (csv-contracts/sui/)
MANIFEST_PATH="../../deployments/deployment-manifest.json"
if [ -f "$MANIFEST_PATH" ]; then
    if command -v python3 &>/dev/null; then
        python3 -c "
import json
import sys
from datetime import datetime

try:
    with open('$MANIFEST_PATH', 'r') as f:
        manifest = json.load(f)
    
    # Update sui deployment info
    if 'deployments' in manifest and 'sui' in manifest['deployments']:
        sui = manifest['deployments']['sui']
        sui['network'] = '$NETWORK'
        sui['package_id'] = '$PACKAGE_ID'
        # registry_id is the RFC-0012 §9.2 destinationContract (shared Registry
        # object) — REQUIRED; the adapter fails closed without it.
        if '$REGISTRY_ID':
            sui['registry_id'] = '$REGISTRY_ID'
        if '$ADMIN_CAP':
            sui['admin_cap'] = '$ADMIN_CAP'
        if '$UPGRADE_CAP':
            sui['upgrade_cap'] = '$UPGRADE_CAP'
        if '$DEPLOY_TX':
            sui['deployment_tx'] = '$DEPLOY_TX'
        sui['verified'] = True
        # A freshly published Registry seeds an empty verifier set (threshold 0);
        # mint stays fail-closed until an AdminCap holder seeds it. Only reset the
        # recorded verifier state when a NEW Registry was created (fresh publish) —
        # an upgrade keeps the existing Registry and its seeded verifiers.
        if '$REGISTRY_ID':
            sui['verifier_set'] = []
            sui['mint_threshold'] = 0
        manifest['updated_at'] = datetime.utcnow().isoformat() + 'Z'

    with open('$MANIFEST_PATH', 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print('Deployment manifest updated successfully')
except Exception as e:
    print(f'ERROR updating manifest: {e}', file=sys.stderr)
    sys.exit(1)
"
        echo "Manifest updated: sui.package_id = ${PACKAGE_ID}"
    else
        echo "WARNING: python3 not found, cannot auto-update deployment manifest"
        echo "Please manually update $MANIFEST_PATH"
        echo "Set deployments.sui.package_id = ${PACKAGE_ID}"
    fi
else
    echo "WARNING: Deployment manifest not found at $MANIFEST_PATH"
fi

# Mirror package_id + registry_id into the per-network chain config for operator
# visibility (the adapter itself resolves authority from the manifest above).
CHAIN_TOML="../../chains/sui-${NETWORK}.toml"
if [ -f "$CHAIN_TOML" ]; then
    echo "Updating $CHAIN_TOML..."
    sed -i "s|^contract_address = \".*\"|contract_address = \"${PACKAGE_ID}\"|" "$CHAIN_TOML"
    sed -i "s|^package_id = \".*\"|package_id = \"${PACKAGE_ID}\"|" "$CHAIN_TOML"
    if [ -n "$REGISTRY_ID" ]; then
        if grep -q "^registry_id = " "$CHAIN_TOML"; then
            sed -i "s|^registry_id = \".*\"|registry_id = \"${REGISTRY_ID}\"|" "$CHAIN_TOML"
        elif grep -q "^# registry_id = " "$CHAIN_TOML"; then
            # Replace the commented placeholder with the real value.
            sed -i "s|^# registry_id = .*|registry_id = \"${REGISTRY_ID}\"|" "$CHAIN_TOML"
        else
            printf 'registry_id = "%s"\n' "$REGISTRY_ID" >> "$CHAIN_TOML"
        fi
    fi
    echo "  ${CHAIN_TOML}: package_id + registry_id updated"
else
    echo "NOTE: $CHAIN_TOML not found; skipping chain-config mirror"
fi

# --- Optional: seed the verifier set now (mint stays fail-closed otherwise) ---
# If CSV_MINT_VERIFIER_PUBKEY (compressed 33-byte secp256k1, 0x optional) is set,
# add it and set threshold=1 in one flow. Sui governance is immediate (AdminCap).
SEEDED=0
if [ -n "${CSV_MINT_VERIFIER_PUBKEY:-}" ] && [ -n "$REGISTRY_ID" ] && [ -n "$ADMIN_CAP" ]; then
    PUB="${CSV_MINT_VERIFIER_PUBKEY}"
    [ "${PUB#0x}" = "$PUB" ] && PUB="0x${PUB}"
    echo "Seeding verifier ${PUB} (add_verifier + set_threshold 1)..."
    if "$SUI" client call --package "$PACKAGE_ID" --module csv_seal --function add_verifier \
            --args "$ADMIN_CAP" "$REGISTRY_ID" "$PUB" --gas-budget 20000000 >/dev/null 2>&1 \
       && "$SUI" client call --package "$PACKAGE_ID" --module csv_seal --function set_threshold \
            --args "$ADMIN_CAP" "$REGISTRY_ID" 1 --gas-budget 20000000 >/dev/null 2>&1; then
        SEEDED=1
        echo "  verifier set SEEDED (1 verifier, threshold 1)"
        if [ -f "$MANIFEST_PATH" ] && command -v python3 &>/dev/null; then
            python3 -c "
import json
m=json.load(open('$MANIFEST_PATH'))
s=m['deployments']['sui']; s['verifier_set']=['$PUB']; s['mint_threshold']=1
json.dump(m,open('$MANIFEST_PATH','w'),indent=2)
" && echo "  manifest: sui.verifier_set/mint_threshold recorded"
        fi
    else
        echo "  WARNING: seeding failed — run the add_verifier/set_threshold commands below manually."
    fi
fi

echo ""
echo "=== DEPLOYMENT SUMMARY ==="
echo "Network:      ${NETWORK}"
echo "Package ID:   ${PACKAGE_ID}"
echo "Registry ID:  ${REGISTRY_ID:-<NOT CAPTURED — see warning above>}"
echo "AdminCap:     ${ADMIN_CAP:-<none>}"
echo "UpgradeCap:   ${UPGRADE_CAP:-<none>}"
echo "Deploy tx:    ${DEPLOY_TX:-<none>}"
echo "Module:       csv_seal::csv_seal"
echo "=========================="
echo ""
if [ "${SEEDED:-0}" = "1" ]; then
    echo "Verifier seeded. Give the runtime the matching key: export CSV_MINT_VERIFIER_KEY=<hex>."
    echo "Full operator guide: csv-docs/runbooks/MINT_VERIFIER_OPERATIONS.md"
    echo ""
    echo "Deployment complete!"
    exit 0
fi
echo "IMPORTANT — mint is FAIL-CLOSED until the verifier set is seeded:"
echo "  A freshly published Registry has an empty verifier set (threshold 0)."
echo "  Set CSV_MINT_VERIFIER_PUBKEY before deploy to auto-seed, or run manually"
echo "  (replace <verifier_pubkey> with the 0x 33-byte compressed key):"
echo ""
echo "    $SUI client call --package ${PACKAGE_ID} --module csv_seal \\"
echo "        --function add_verifier --args ${ADMIN_CAP} ${REGISTRY_ID} <verifier_pubkey> \\"
echo "        --gas-budget 20000000"
echo "    $SUI client call --package ${PACKAGE_ID} --module csv_seal \\"
echo "        --function set_threshold --args ${ADMIN_CAP} ${REGISTRY_ID} 1 \\"
echo "        --gas-budget 20000000"
echo ""
echo "  Then record verifier_set + mint_threshold in deployments/deployment-manifest.json"
echo "  and provide the matching signing key to the runtime (with_verifier_key)."
echo ""

echo "Deployment complete!"
