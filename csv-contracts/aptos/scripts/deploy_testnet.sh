#!/usr/bin/env bash
# Deploy CSV Seal contracts on Aptos Testnet using REST API
# Uses the funded wallet from wallet/aptos-test.txt
# Address: 0x4e8e35b340112baca1ca18e422da4c7d447d17fa560fbfd0e0c24de3de239b1b
#
# ⚠️  Requires APTOS_PRIVATE_KEY environment variable.
#     Copy .env.example to .env and fill in your key.

set -euo pipefail

APTOS_PRIVATE_KEY="${APTOS_PRIVATE_KEY:?⚠️  APTOS_PRIVATE_KEY is not set. Copy .env.example to .env and fill in your key.}"
APTOS_ACCOUNT="0x4e8e35b340112baca1ca18e422da4c7d447d17fa560fbfd0e0c24de3de239b1b"
TESTNET_RPC="https://fullnode.testnet.aptoslabs.com/v1"
FAUCET_URL="https://faucet.testnet.aptoslabs.com"

echo "=== Aptos Testnet CSV Seal Deployment ==="
echo ""
echo "Account: ${APTOS_ACCOUNT}"
echo ""

# Check balance
echo "Checking balance..."
BALANCE=$(curl -s "${TESTNET_RPC}/accounts/${APTOS_ACCOUNT}/balance/0x1::aptos_coin::AptosCoin")
echo "Balance: ${BALANCE} octas ($(( BALANCE / 100000000 )) APT)"
echo ""

if [ "${BALANCE}" -lt 100000000 ]; then
    echo "ERROR: Insufficient balance. Need at least 1 APT (100,000,000 octas)"
    exit 1
fi

echo "✅ Sufficient balance for deployment"
echo ""

# Check if aptos CLI is available
if command -v aptos &>/dev/null; then
    echo "Using aptos CLI..."
    echo ""

    # Initialize profile if needed
    if ! aptos config show-profiles --profile default 2>/dev/null | grep -q "${APTOS_ACCOUNT}"; then
        echo "Initializing aptos CLI profile..."
        aptos init --network testnet --private-key ${APTOS_PRIVATE_KEY} --assume-yes 2>&1 || {
            echo "Profile may already exist, continuing..."
        }
        echo ""
    fi

    # Update Move.toml with actual account address
    cd "$(dirname "$0")/.."
    sed -i "s/csv_seal = \"0x0\"/csv_seal = \"${APTOS_ACCOUNT}\"/" contracts/Move.toml
    sed -i "s/CSV = \"0x0\"/CSV = \"${APTOS_ACCOUNT}\"/" contracts/Move.toml

    echo "Updated Move.toml with account address"
    echo ""

    # Compile
    echo "Compiling Move package..."
    aptos move compile --package-dir contracts 2>&1 | tail -10
    echo ""

    # Publish
    echo "Publishing to testnet..."
    PUBLISH_RESULT=$(aptos move publish \
        --package-dir contracts \
        --profile default \
        --assume-yes \
        --json 2>&1)

    echo "$PUBLISH_RESULT" > scripts/deploy-output-testnet.json

    # Extract transaction hash
    TX_HASH=$(echo "$PUBLISH_RESULT" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('hash', ''))" 2>/dev/null || echo "")

    echo ""
    echo "=== DEPLOYMENT SUMMARY ==="
    echo "Account: ${APTOS_ACCOUNT}"
    echo "Transaction: ${TX_HASH}"
    echo "Network: testnet"
    echo "Module: ${APTOS_ACCOUNT}::csv_seal::CSVSeal"
    echo "=========================="
    echo ""

    # Initialize module
    echo "Initializing CSVSeal module..."
    aptos move run \
        --function-id "${APTOS_ACCOUNT}::csv_seal::CSVSeal::initialize_module" \
        --profile default \
        --assume-yes \
        --json 2>&1 | tee scripts/registry-init-testnet.json | tail -5

    echo ""
    echo "✅ Deployment complete!"
    echo ""
    echo "Module address: ${APTOS_ACCOUNT}"
    echo "Module path: ${APTOS_ACCOUNT}::csv_seal::CSVSeal"
    echo ""
    echo "Next steps:"
    echo "1. Verify deployment: curl ${TESTNET_RPC}/accounts/${APTOS_ACCOUNT}/modules"
    echo "2. Create a seal: aptos move run --function-id ${APTOS_ACCOUNT}::csv_seal::CSVSeal::create_seal --args u64:12345"
    echo "3. Run cross-chain e2e tests"

else
    echo "WARNING: aptos CLI not available."
    echo "Manual deployment required."
    echo ""
    echo "To deploy manually:"
    echo "1. Install aptos CLI: cargo install --git https://github.com/aptos-labs/aptos-core.git aptos"
    echo "2. Run: ./scripts/deploy_testnet.sh"
    echo ""
    echo "Or use the REST API directly:"
    echo "  POST ${TESTNET_RPC}/transactions"
    echo "  With signed transaction containing the compiled Move bytecode"
    exit 1
fi
