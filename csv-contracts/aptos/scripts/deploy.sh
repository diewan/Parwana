#!/usr/bin/env bash
# Deploy CSV Seal contracts on Aptos Testnet
# Usage: ./deploy.sh [network] [aptos-cli-path]
#   network: testnet (default), devnet, mainnet
#   aptos-cli-path: path to aptos binary (default: aptos)
# Environment variables (optional):
#   CSV_APTOS_ADDRESS - Account address from unified state
#   CSV_APTOS_PRIVATE_KEY - Private key from unified state

set -euo pipefail

NETWORK="${1:-testnet}"
APTOS="${2:-aptos}"

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
    
    # Export config location for all subsequent aptos commands
    export APTOS_CONFIG="${PWD}/.aptos/config.yaml"
    
    # Debug: show config content
    echo "  Config file (.aptos/config.yaml):"
    cat ".aptos/config.yaml" | sed 's/^/    /'
    
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
    ACCOUNT=$("$APTOS" config show-profiles --profile default 2>/dev/null | grep "account" | head -1 | awk '{print $2}' || echo "")
    
    # For default profile, don't override config location
    export APTOS_CONFIG=""
fi

echo ""

# Backup original Move.toml and modify addresses to placeholders
MOVE_TOML="contracts/Move.toml"
MOVE_TOML_BACKUP="${TEMP_DIR}/Move.toml.backup"
cp "${MOVE_TOML}" "${MOVE_TOML_BACKUP}"

# Replace hardcoded addresses with placeholders that can be overridden
sed -i "s/^csv_seal = \"0x[0-9a-f]*\"/csv_seal = \"_\"/" "${MOVE_TOML}"
sed -i "s/^CSV = \"0x[0-9a-f]*\"/CSV = \"_\"/" "${MOVE_TOML}"

# Build the package with the correct address
echo "Building Move package..."
"$APTOS" move compile \
    --package-dir contracts \
    --named-addresses "csv_seal=${ACCOUNT},CSV=${ACCOUNT}" 2>&1 | tail -5
echo ""

# Publish to testnet with the correct address
echo "Publishing to ${NETWORK}..."
if [ -n "${APTOS_CONFIG:-}" ]; then
    # Use explicit config file for csv_deploy profile
    PUBLISH_OUTPUT=$("$APTOS" move publish \
        --package-dir contracts \
        --profile "${APTOS_PROFILE}" \
        --named-addresses "csv_seal=${ACCOUNT},CSV=${ACCOUNT}" \
        --assume-yes 2>&1) || {
        echo "ERROR: Publish failed"
        echo "$PUBLISH_OUTPUT"
        # Restore original Move.toml on failure
        cp "${MOVE_TOML_BACKUP}" "${MOVE_TOML}"
        rm -rf "${TEMP_DIR}" .aptos 2>/dev/null || true
        exit 1
    }
else
    # Use default profile from global config
    PUBLISH_OUTPUT=$("$APTOS" move publish \
        --package-dir contracts \
        --profile "${APTOS_PROFILE}" \
        --named-addresses "csv_seal=${ACCOUNT},CSV=${ACCOUNT}" \
        --assume-yes 2>&1) || {
        echo "ERROR: Publish failed"
        echo "$PUBLISH_OUTPUT"
        # Restore original Move.toml on failure
        cp "${MOVE_TOML_BACKUP}" "${MOVE_TOML}"
        rm -rf "${TEMP_DIR}" 2>/dev/null || true
        exit 1
    }
fi

# Restore original Move.toml after successful deployment
cp "${MOVE_TOML_BACKUP}" "${MOVE_TOML}"

echo "$PUBLISH_OUTPUT" > "scripts/deploy-output-${NETWORK}.txt"

# Extract transaction hash from text output (look for lines containing transaction hash)
TX_HASH=$(echo "$PUBLISH_OUTPUT" | grep -i "transaction\|hash\|committed" | head -1 | sed 's/.*: *//' | tr -d '"' | tr -d ' ' || echo "")

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
echo "Next steps:"
echo "1. The package is published under your account address: ${ACCOUNT}"
echo "2. Initialize LockRegistry:"
echo "   aptos move run --function-id ${ACCOUNT}::csv_seal::init_registry --profile ${APTOS_PROFILE}"
echo ""

# Initialize the LockRegistry
echo "Initializing LockRegistry..."
echo "  Waiting for publish transaction to be committed..."
sleep 5

# Verify config file exists
if [ -n "${APTOS_CONFIG:-}" ] && [ ! -f ".aptos/config.yaml" ]; then
    echo "  ERROR: Config file .aptos/config.yaml not found!"
    echo "  Current directory: ${PWD}"
    ls -la .aptos/ 2>/dev/null || echo "  .aptos directory does not exist"
    exit 1
fi

# Retry init up to 3 times with delay
INIT_SUCCESS=false
for i in 1 2 3; do
    echo "  Attempt $i/3..."
    if [ -n "${APTOS_CONFIG:-}" ]; then
        # Use explicit config for csv_deploy profile
        if "$APTOS" move run \
            --function-id "${ACCOUNT}::csv_seal::init_registry" \
            --profile "${APTOS_PROFILE}" \
            --assume-yes 2>&1 | tee "scripts/registry-init-${NETWORK}.txt" | tail -5; then
            INIT_SUCCESS=true
            break
        fi
    else
        # Use default profile from global config
        if "$APTOS" move run \
            --function-id "${ACCOUNT}::csv_seal::init_registry" \
            --profile "${APTOS_PROFILE}" \
            --assume-yes 2>&1 | tee "scripts/registry-init-${NETWORK}.txt" | tail -5; then
            INIT_SUCCESS=true
            break
        fi
    fi
    if [ $i -lt 3 ]; then
        echo "  Retrying in 10 seconds..."
        sleep 10
    fi
done

if [ "$INIT_SUCCESS" = false ]; then
    echo "WARNING: Failed to initialize LockRegistry. You may need to run it manually:"
    if [ -n "${APTOS_CONFIG:-}" ]; then
        echo "  aptos move run --function-id ${ACCOUNT}::csv_seal::init_registry --profile ${APTOS_PROFILE}"
        echo "  (from directory: ${PWD})"
    else
        echo "  aptos move run --function-id ${ACCOUNT}::csv_seal::init_registry --profile ${APTOS_PROFILE}"
    fi
fi

# Cleanup temp directory and .aptos
if [ -n "${TEMP_DIR:-}" ] && [ -d "${TEMP_DIR}" ]; then
    rm -rf "${TEMP_DIR}"
fi
if [ -d ".aptos" ]; then
    rm -rf .aptos
fi

echo ""
echo "Deployment complete!"
