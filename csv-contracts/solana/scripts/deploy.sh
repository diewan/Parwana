#!/usr/bin/env bash
# Deploy CSV Seal program on Solana Devnet/Testnet/Mainnet
# Usage: ./deploy.sh [network] [anchor-path]
#   network: devnet (default), testnet, mainnet, localnet
#   anchor-path: path to anchor binary (default: anchor)

set -euo pipefail

NETWORK="${1:-devnet}"
ANCHOR="${2:-anchor}"

echo "=== Solana ${NETWORK} Deployment ==="
echo ""

# Check dependencies
if ! command -v "$ANCHOR" &>/dev/null; then
    echo "ERROR: Anchor not found. Install with:"
    echo "  npm install -g @coral-xyz/anchor-cli"
    exit 1
fi

if ! command -v solana &>/dev/null; then
    echo "ERROR: Solana CLI not found. Install from:"
    echo "  https://docs.solana.com/cli/install"
    exit 1
fi

cd "$(dirname "$0")/../contracts"

# Setup wallet - prefer unified csv-wallet if available, otherwise fall back to Solana CLI default
KEYPAIR_ARG=""
KEYPAIR_FILE=""

# 1. If user explicitly provides CSV_SOLANA_KEYPAIR env var, use it (existing behaviour)
if [ -n "${CSV_SOLANA_KEYPAIR:-}" ] && [ -f "${CSV_SOLANA_KEYPAIR:-}" ]; then
    KEYPAIR_FILE="$CSV_SOLANA_KEYPAIR"
    echo "Using unified wallet keypair from CSV_SOLANA_KEYPAIR: $KEYPAIR_FILE"
    KEYPAIR_ARG="--keypair $KEYPAIR_FILE"
else
    # 2. Attempt to load keypair from the legacy csv-wallet JSON file (~/.csv/wallet/csv-wallet.json)
    CSV_WALLET_JSON="$HOME/.csv/wallet/csv-wallet.json"
    if [ -f "$CSV_WALLET_JSON" ]; then
        # Extract the first private_key for the Solana chain (if present)
        # The JSON structure is an array of accounts; we look for chain == "solana"
        SOLANA_PRIV_KEY=$(jq -r '.accounts[] | select(.chain|ascii_downcase=="solana") | .private_key' "$CSV_WALLET_JSON" | head -n1)
        if [ -n "$SOLANA_PRIV_KEY" ] && [ "$SOLANA_PRIV_KEY" != "null" ]; then
            # Write the private key to a temporary keypair file in the expected format
            TMP_KEYPAIR=$(mktemp)
            echo "$SOLANA_PRIV_KEY" > "$TMP_KEYPAIR"
            chmod 600 "$TMP_KEYPAIR"
            KEYPAIR_FILE="$TMP_KEYPAIR"
            echo "Using Solana keypair extracted from csv-wallet.json"
            KEYPAIR_ARG="--keypair $KEYPAIR_FILE"
        fi
    fi
fi

# Get active wallet
echo "Active wallet:"
if [ -n "$KEYPAIR_ARG" ]; then
    solana-keygen pubkey "$KEYPAIR_FILE"
else
    solana address 2>/dev/null || {
        echo "No active wallet. Run: solana-keygen new"
        exit 1
    }
fi
echo ""


# Determine RPC URL based on network
RPC_URL=""
case "$NETWORK" in
    devnet)
        RPC_URL="https://api.devnet.solana.com"
        ;;
    testnet)
        RPC_URL="https://api.testnet.solana.com"
        ;;
    mainnet|mainnet-beta)
        RPC_URL="https://api.mainnet-beta.solana.com"
        ;;
    localnet)
        RPC_URL="http://localhost:8899"
        ;;
    *)
        RPC_URL="https://api.devnet.solana.com"
        ;;
esac
# Ensure RPC_URL is defined to avoid unbound variable errors under set -u
RPC_URL="${RPC_URL:?RPC_URL is not set}"

# Check balance (use explicit --url to avoid config dependency)
echo "Wallet balance:"
if [ -n "$KEYPAIR_ARG" ]; then
    solana balance --keypair "$KEYPAIR_FILE" --url "$RPC_URL" 2>/dev/null || echo "Unable to fetch balance (may need airdrop)"
else
    solana balance --url "$RPC_URL" 2>/dev/null || echo "Unable to fetch balance (may need airdrop)"
fi
echo ""

# Build the program (no wallet needed for build)
echo "Building Anchor program..."
$ANCHOR build 2>&1 | tail -10
echo ""

# Setup Anchor wallet arguments
declare -a ANCHOR_ARGS
ANCHOR_ARGS=("deploy" "--provider.cluster" "$NETWORK")

# Export ANCHOR_WALLET environment variable if using custom keypair
if [ -n "$KEYPAIR_ARG" ]; then
    export ANCHOR_WALLET="$KEYPAIR_FILE"
fi

# Deploy
echo "Deploying to ${NETWORK}..."
if [ -n "$KEYPAIR_ARG" ]; then
    echo "Deploying with csv wallet keypair..."
    echo "DEBUG: KEYPAIR_FILE=$KEYPAIR_FILE"
    
    # Verify keypair file is valid JSON
    if ! jq empty "$KEYPAIR_FILE" 2>/dev/null; then
        echo "ERROR: Keypair file is not valid JSON"
        cat "$KEYPAIR_FILE"
        exit 1
    fi
    
    echo "DEBUG: Keypair file contents (first 50 chars):"
    head -c 50 "$KEYPAIR_FILE"
    echo ""
    echo ""
    
    echo "DEBUG: Running Anchor deploy with:"
    echo "  Command: $ANCHOR ${ANCHOR_ARGS[@]}"
    
    deploy_output=$($ANCHOR "${ANCHOR_ARGS[@]}" 2>&1)
    deploy_exit_code=$?
    
    echo "DEBUG: Deploy command exit code: $deploy_exit_code"
else
    echo "Deploying with default wallet..."
    deploy_output=$($ANCHOR "${ANCHOR_ARGS[@]}" 2>&1)
    deploy_exit_code=$?
fi

echo "$deploy_output"
echo ""

# Check if deploy failed
if [ $deploy_exit_code -ne 0 ]; then
    echo "ERROR: Deploy command failed with exit code $deploy_exit_code"
    
    # Fallback to solana program deploy if anchor fails and we have a keypair
    if [ -n "$KEYPAIR_ARG" ] && [ -f "target/deploy/csv_seal.so" ]; then
        echo ""
        echo "Attempting fallback: using solana program deploy directly..."
        
        # Try direct deployment
        deploy_output=$(solana program deploy --keypair "$KEYPAIR_FILE" --url "$RPC_URL" "target/deploy/csv_seal.so" 2>&1)
        deploy_exit_code=$?
        
        echo "$deploy_output"
        
        if [ $deploy_exit_code -ne 0 ]; then
            echo "ERROR: Direct deploy also failed"
            exit 1
        fi
    else
        exit 1
    fi
fi

# Extract program ID from the output
program_id=$(echo "$deploy_output" | grep -oP 'Program Id: \K[0-9A-Za-z]{32,44}' || echo "")

if [ -z "$program_id" ]; then
    # Try to get from Anchor.toml or keypair (use explicit keypair and url)
    if [ -n "$KEYPAIR_ARG" ]; then
        program_id=$(solana-keygen pubkey target/deploy/csv_seal-keypair.json --keypair "$KEYPAIR_FILE" --url "$RPC_URL" 2>/dev/null || echo "")
    else
        program_id=$(solana-keygen pubkey target/deploy/csv_seal-keypair.json --url "$RPC_URL" 2>/dev/null || echo "")
    fi
fi

if [ -z "$program_id" ]; then
    echo "WARNING: Could not extract program ID from deploy output."
    echo "Check the output above for the program address."
else
    echo "=== DEPLOYMENT SUMMARY ==="
    echo "Program ID: ${program_id}"
    echo "Network: ${NETWORK}"
    echo "=========================="
    echo ""
    
    # Save to state file
    mkdir -p "../scripts"
    cat > "../scripts/deploy-${NETWORK}.json" <<EOF
{
  "program_id": "${program_id}",
  "network": "${NETWORK}",
  "deployed_at": $(date +%s),
  "module": "csv_seal"
}
EOF
    
    echo "Deployment info saved to ../scripts/deploy-${NETWORK}.json"
    echo ""
fi

# Initialize the LockRegistry
echo "Initializing LockRegistry..."
if [ -n "$KEYPAIR_ARG" ]; then
    $ANCHOR run initialize --provider.cluster "$NETWORK" --provider.wallet "$KEYPAIR_FILE" 2>&1 || {
        echo "Note: Registry initialization may require manual execution:"
        echo "  anchor run initialize --provider.cluster ${NETWORK} --provider.wallet <KEYPAIR>"
    }
else
    $ANCHOR run initialize --provider.cluster "$NETWORK" 2>&1 || {
        echo "Note: Registry initialization may require manual execution:"
        echo "  anchor run initialize --provider.cluster ${NETWORK}"
    }
fi

echo ""
echo "Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Update Anchor.toml with the program ID: ${program_id}"
echo "2. Update your csv-cli configuration to use this program ID"
echo "3. Run tests: anchor test --provider.cluster ${NETWORK}"
