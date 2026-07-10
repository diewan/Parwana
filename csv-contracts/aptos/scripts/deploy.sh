#!/usr/bin/env bash
# Deploy CSV Seal contracts on Aptos Testnet
# Usage: ./deploy.sh [network] [aptos-cli-path]
#   network: testnet (default), devnet, mainnet
#   aptos-cli-path: path to aptos binary (default: aptos)
# Environment variables (optional):
#   CSV_APTOS_ADDRESS - Account address from unified state
#   CSV_APTOS_PRIVATE_KEY - Private key from unified state
#   CSV_APTOS_PROFILE - Aptos CLI profile to load from $HOME/.aptos/config.yaml

set -euo pipefail

NETWORK="${1:-testnet}"
APTOS="${2:-aptos}"

# Resolve an explicitly requested global Aptos profile before changing into the
# contract directory. Aptos CLI profiles are workspace-relative, so looking it
# up after `cd` would incorrectly report that the profile does not exist.
if [ -n "${CSV_APTOS_PROFILE:-}" ] && [ -z "${CSV_APTOS_ADDRESS:-}" ] && [ -z "${CSV_APTOS_PRIVATE_KEY:-}" ]; then
    CSV_APTOS_ADDRESS=$(cd "${HOME}" && "$APTOS" config show-profiles --profile "${CSV_APTOS_PROFILE}" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['Result']['${CSV_APTOS_PROFILE}']['account'])")
    CSV_APTOS_PRIVATE_KEY=$(cd "${HOME}" && "$APTOS" config show-private-key --profile "${CSV_APTOS_PROFILE}" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['Result'])")
fi

echo "=== Aptos ${NETWORK} Deployment ==="
echo ""

# Check dependencies
if ! command -v "$APTOS" &>/dev/null; then
    echo "ERROR: aptos CLI not found. Install with: cargo install --git https://github.com/aptos-labs/aptos-core.git aptos"
    exit 1
fi

cd "$(dirname "$0")/.."

# Determine which account to use
if [ -n "${CSV_APTOS_ADDRESS:-}" ] && [ -n "${CSV_APTOS_PRIVATE_KEY:-}" ]; then
    # Use unified state account - create a temporary profile
    echo "Using account from unified state: ${CSV_APTOS_ADDRESS}"
    
    # Create a temporary profile directory
    TEMP_DIR=$(mktemp -d)
    PROFILE_DIR="${TEMP_DIR}/.aptos"
    mkdir -p "${PROFILE_DIR}"
    
    # Generate the config.yaml with unified state credentials
    # Network must be capitalized: Mainnet, Testnet, Devnet
    case "${NETWORK}" in
        testnet) APTOS_NETWORK_CAP="Testnet" ;;
        devnet) APTOS_NETWORK_CAP="Devnet" ;;
        mainnet) APTOS_NETWORK_CAP="Mainnet" ;;
        *) APTOS_NETWORK_CAP="${NETWORK}" ;;
    esac
    
    # Create .aptos directory and use aptos init to generate proper config
    mkdir -p ".aptos"
    
    # Write private key to temp file for aptos init
    PRIV_KEY_FILE="${TEMP_DIR}/private_key"
    echo "${CSV_APTOS_PRIVATE_KEY}" > "${PRIV_KEY_FILE}"
    
    # Initialize aptos config with the private key
    # This creates proper profile with all required fields (including public_key)
    "$APTOS" init \
        --profile csv_deploy \
        --network "${APTOS_NETWORK_CAP}" \
        --private-key-file "${PRIV_KEY_FILE}" \
        --assume-yes \
        --skip-faucet 2>/dev/null || {
        echo "ERROR: Failed to initialize aptos profile with provided private key"
        rm -rf "${TEMP_DIR}" .aptos 2>/dev/null || true
        exit 1
    }
    
    APTOS_PROFILE="csv_deploy"
    ACCOUNT="${CSV_APTOS_ADDRESS}"
    
    # The Aptos CLI resolves the profile from .aptos/config.yaml in the
    # current directory.  Do not print that file: it contains the private key.
    echo "  Created temporary profile for deployment"
else
    # Use default profile from aptos CLI config
    echo "Checking Aptos CLI profile..."
    "$APTOS" config show-profiles 2>/dev/null || {
        echo "No profile found. Run: aptos init --network ${NETWORK}"
        exit 1
    }
    
    # Ensure TEMP_DIR is defined for Move.toml backup
    if [ -z "${TEMP_DIR:-}" ]; then
        TEMP_DIR=$(mktemp -d)
    fi
    
    APTOS_PROFILE="default"
    ACCOUNT=$("$APTOS" config show-profiles --profile default 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['Result']['default']['account'])" 2>/dev/null || echo "")
    
fi

# Persist and pass one canonical address representation everywhere.
if [ -z "${ACCOUNT:-}" ]; then
    echo "ERROR: Aptos deployment account is empty"
    exit 1
fi
ACCOUNT="0x${ACCOUNT#0x}"

echo ""

# Backup original Move.toml and modify addresses to placeholders
MOVE_TOML="contracts/Move.toml"
MOVE_TOML_BACKUP="${TEMP_DIR}/Move.toml.backup"
cp "${MOVE_TOML}" "${MOVE_TOML_BACKUP}"

# Replace hardcoded addresses with placeholders that can be overridden
sed -i "s/^csv_seal = \"[0-9a-f]*\"/csv_seal = \"_\"/" "${MOVE_TOML}"
sed -i "s/^CSV = \"[0-9a-f]*\"/CSV = \"_\"/" "${MOVE_TOML}"

# Build the package with the correct address
echo "Building Move package..."

# Clean previous builds to ensure fresh compilation
echo "Cleaning previous builds..."
rm -rf build/

# Build from scratch
"$APTOS" move compile \
    --package-dir contracts \
    --named-addresses "csv_seal=${ACCOUNT},CSV=${ACCOUNT}" 2>&1 | tail -5
echo ""

# Analyze a failed publish and give actionable guidance. Aptos has NO un-publish:
# a module can only be UPGRADED in place if the change is backward-compatible.
# A breaking change (e.g. changed struct fields or #[event] attributes) is
# rejected and must go to a fresh account.
analyze_publish_failure() {
    echo "ERROR: Publish failed"
    echo "$PUBLISH_OUTPUT" | tail -20
    cp "${MOVE_TOML_BACKUP}" "${MOVE_TOML}" 2>/dev/null || true
    rm -rf "${TEMP_DIR}" .aptos 2>/dev/null || true
    if echo "$PUBLISH_OUTPUT" | grep -qiE 'EVENT_METADATA_VALIDATION_ERROR|BACKWARD_INCOMPAT|incompatible|compatibility'; then
        cat <<EOF

============================================================
INCOMPATIBLE UPGRADE: account ${ACCOUNT} already has a csv_seal module whose
on-chain layout/events differ from this code. Aptos rejects incompatible
in-place upgrades and cannot delete a published module. Choose ONE:

  1) Keep the account: make the change COMPATIBLE (only ADD items; do not change
     or reorder existing struct fields or #[event] struct attributes), then
     re-run this script. The @csv_seal address and existing resources are kept.

  2) Use a FRESH account (new @csv_seal address) for a breaking change:
       aptos init --profile csvmint --network ${NETWORK} --private-key <hex> --assume-yes
       # fund it (aptos account transfer / faucet), then re-run this script so it
       # publishes under that account. Update deployments/deployment-manifest.json
       # and chains/aptos-*.toml to the new module_address afterwards.

  DO NOT 'aptos move deploy-object' this contract: init_registry /
  init_mint_authority assert signer == @csv_seal and store resources there, and
  an object address exposes no signer to call them — the module would be
  permanently uninitializable.
============================================================
EOF
    fi
    exit 1
}

# Publish to testnet with the correct address
echo "Publishing to ${NETWORK}..."
PUBLISH_OUTPUT=$("$APTOS" move publish \
    --package-dir contracts \
    --profile "${APTOS_PROFILE}" \
    --named-addresses "csv_seal=${ACCOUNT},CSV=${ACCOUNT}" \
    --assume-yes 2>&1) || analyze_publish_failure

# Restore original Move.toml after successful deployment
cp "${MOVE_TOML_BACKUP}" "${MOVE_TOML}"

echo "$PUBLISH_OUTPUT" > "scripts/deploy-output-${NETWORK}.txt"

# Aptos CLI v9 emits the committed transaction as JSON. Preserve that exact hash
# in the deployment manifest rather than retaining the previous deployment's
# transaction reference.
TX_HASH=$(echo "$PUBLISH_OUTPUT" | sed -nE 's/.*"transaction_hash": *"(0x[0-9a-fA-F]+)".*/\1/p' | head -1)

# Package ID is the account address in Aptos
PACKAGE_ID="${ACCOUNT}"

echo ""
echo "=== DEPLOYMENT SUMMARY ==="
echo "Account: ${ACCOUNT}"
echo "Package: ${PACKAGE_ID}"
echo "Network: ${NETWORK}"
echo "Module: csv_seal::csv_seal"
echo "=========================="
echo ""
echo "Initializing module (this is what actually enables the module)..."
echo "  Waiting for publish transaction to be committed..."
sleep 5

# Verify the temporary profile exists.
if [ "${APTOS_PROFILE}" = "csv_deploy" ] && [ ! -f ".aptos/config.yaml" ]; then
    echo "  ERROR: Config file .aptos/config.yaml not found!"
    echo "  Current directory: ${PWD}"
    ls -la .aptos/ 2>/dev/null || echo "  .aptos directory does not exist"
    exit 1
fi

# Common profile/config args for `aptos move run`.
declare -a RUN_ARGS=(--profile "${APTOS_PROFILE}" --assume-yes)

# Run an entry function, treating "already initialized" as success so re-running
# the script (or re-seeding) is idempotent. Extra args (e.g. --args ...) precede.
run_init() {
    local fn="$1"; shift
    echo "  -> ${fn} $*"
    local out
    if out=$("$APTOS" move run --function-id "${ACCOUNT}::CSVSeal::${fn}" "$@" "${RUN_ARGS[@]}" 2>&1); then
        echo "     ok"
        return 0
    fi
    if echo "$out" | grep -qiE 'RESOURCE_ALREADY_EXISTS|EAnchorDataExists|already.*exist|Move abort.*0x3'; then
        echo "     already initialized (ok)"
        return 0
    fi
    echo "$out" | tail -6
    return 1
}

# The mint destination needs: event handle, the LockRegistry (holds the replay
# tables), and the MintAuthority (verifier set). All assert signer == @csv_seal.
run_init initialize_module || {
    echo "  ERROR: initialize_module is required"
    exit 1
}
run_init init_registry || {
    echo "  ERROR: init_registry is required"
    exit 1
}
run_init init_sanad_registry || {
    echo "  ERROR: init_sanad_registry is required for canonical Sanad creation"
    exit 1
}

# Seed the verifier set if the operator supplied a pubkey; otherwise mint stays
# fail-closed and the operator seeds it later (see runbook).
if [ -n "${CSV_MINT_VERIFIER_PUBKEY:-}" ]; then
    PUBHEX="${CSV_MINT_VERIFIER_PUBKEY#0x}"
    if run_init init_mint_authority --args "hex:${PUBHEX}"; then
        echo "  verifier set SEEDED (1 verifier, threshold 1)"
    else
        echo "  WARNING: init_mint_authority failed — seed manually (see runbook)"
    fi
else
    echo ""
    echo "NOTE: CSV_MINT_VERIFIER_PUBKEY not set — MintAuthority NOT seeded; mint fails closed."
    echo "  Seed later (verifier = compressed 33-byte secp256k1 pubkey):"
    echo "    aptos move run --function-id ${ACCOUNT}::CSVSeal::init_mint_authority \\"
    echo "        --args hex:<verifier_pubkey> --profile ${APTOS_PROFILE} --assume-yes"
    echo "  Rotate later is TIMELOCKED (7 days) — two steps:"
    echo "    schedule_verifier_update --args hex:<pubkey> bool:<add?> u64:<new_threshold>"
    echo "    execute_verifier_update            # after the 7-day timelock elapses"
fi

# Update ~/.csv/config.toml with the deployed module address
CONFIG_FILE="$HOME/.csv/config.toml"
if [ -f "$CONFIG_FILE" ]; then
    echo "Updating $CONFIG_FILE..."
    # Use sed to update contract_address for aptos chain
    if command -v sed &>/dev/null; then
        # Create backup
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%s)"
        # Update contract_address for aptos chain
        sed -i.bak "/\[chains.aptos\]/,/^\[/ s|contract_address = \".*\"|contract_address = \"${PACKAGE_ID}\"|" "$CONFIG_FILE"
        rm -f "${CONFIG_FILE}.bak"
        echo "  aptos contract_address updated to ${PACKAGE_ID}"
    else
        echo "WARNING: sed not found, cannot auto-update config file"
        echo "Please manually update $CONFIG_FILE"
        echo "Set chains.aptos.contract_address = ${PACKAGE_ID}"
    fi
else
    echo "WARNING: $CONFIG_FILE not found, skipping config update"
fi

# Update deployment manifest
echo "Updating deployment manifest..."
# Calculate manifest path from current directory (csv-contracts/aptos/)
MANIFEST_PATH="../../deployments/deployment-manifest.json"
if [ -f "$MANIFEST_PATH" ]; then
    if command -v python3 &>/dev/null; then
        python3 -c "
import json
import sys
from datetime import datetime, timezone

try:
    with open('$MANIFEST_PATH', 'r') as f:
        manifest = json.load(f)
    
    # Update aptos deployment info
    if 'deployments' in manifest and 'aptos' in manifest['deployments']:
        apt = manifest['deployments']['aptos']
        apt['network'] = '$NETWORK'
        # module_address (@csv_seal) is the RFC-0012 §9.2 destinationContract.
        apt['module_address'] = '$PACKAGE_ID'
        apt['deployment_tx'] = '$TX_HASH' or None
        apt['verified'] = True
        apt['deployment_type'] = 'account_publish'
        # Record the seeded verifier if init_mint_authority ran this deploy;
        # otherwise reset to empty so the manifest never advertises stale keys
        # (mint stays fail-closed until seeded).
        seeded = '${CSV_MINT_VERIFIER_PUBKEY:-}'.strip()
        if seeded:
            pk = seeded if seeded.startswith('0x') else '0x' + seeded
            apt['verifier_set'] = [pk]
            apt['mint_threshold'] = 1
        else:
            apt['verifier_set'] = []
            apt['mint_threshold'] = 0
        manifest['updated_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    with open('$MANIFEST_PATH', 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print('Deployment manifest updated successfully')
except Exception as e:
    print(f'ERROR updating manifest: {e}', file=sys.stderr)
    sys.exit(1)
"
        echo "Manifest updated: aptos.module_address = ${PACKAGE_ID}"
    else
        echo "WARNING: python3 not found, cannot auto-update deployment manifest"
        echo "Please manually update $MANIFEST_PATH"
        echo "Set deployments.aptos.module_address = ${PACKAGE_ID}"
    fi
else
    echo "WARNING: Deployment manifest not found at $MANIFEST_PATH"
fi

# Keep the checked-in chain configuration aligned with the deployed module.
CHAIN_CONFIG="../../chains/aptos-${NETWORK}.toml"
if [ -f "$CHAIN_CONFIG" ]; then
    sed -i \
        -e "s|^contract_address = \".*\"|contract_address = \"${PACKAGE_ID}\"|" \
        -e "s|^module_address = \".*\"|module_address = \"${PACKAGE_ID}\"|" \
        "$CHAIN_CONFIG"
    echo "Chain config updated: ${CHAIN_CONFIG}"
else
    echo "WARNING: Chain config not found at ${CHAIN_CONFIG}"
fi

# Cleanup temp directory and .aptos
if [ -n "${TEMP_DIR:-}" ] && [ -d "${TEMP_DIR}" ]; then
    rm -rf "${TEMP_DIR}"
fi
if [ -d ".aptos" ]; then
    rm -rf .aptos
fi

echo ""
echo "To finish enabling mint:"
if [ -n "${CSV_MINT_VERIFIER_PUBKEY:-}" ]; then
    echo "  - Verifier was seeded above. Record verifier_set + mint_threshold in"
    echo "    deployments/deployment-manifest.json, and give the runtime the matching"
    echo "    private key: export CSV_MINT_VERIFIER_KEY=<hex>."
else
    echo "  - Seed the verifier (see the note above), then export CSV_MINT_VERIFIER_KEY=<hex>."
fi
echo "  Full operator guide: csv-docs/runbooks/MINT_VERIFIER_OPERATIONS.md"
echo ""
echo "Deployment complete!"
