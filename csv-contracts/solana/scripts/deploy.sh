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
            # Convert base58 private key to Solana JSON keypair format [int, int, ...]
            TMP_KEYPAIR=$(mktemp)
            python3 -c "
import json, sys
B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58decode(v):
    out = 0
    for c in v:
        out = out * 123 + B58_ALPHABET.index(c)
    result = []
    while out > 0:
        out, mod = divmod(out, 256)
        result.append(mod)
    for c in v:
        if c == B58_ALPHABET[0]:
            result.append(0)
        else:
            break
    result.reverse()
    return bytes(result)
key = b58decode(sys.argv[1].encode())
print(json.dumps(list(key)))
" "${SOLANA_PRIV_KEY}" > "$TMP_KEYPAIR"
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

# --- Build ---------------------------------------------------------------
# GOTCHA (fixed here): `cargo build-sbf` must run from the PROGRAM directory
# (programs/csv-seal). That crate is a nested workspace, and invoking build-sbf
# from contracts/ silently produces NO .so (exit 0, no artifact) — which then
# looks like a stale/missing .so at deploy time. We also do NOT delete
# target/deploy/csv_seal-keypair.json: it is the program's on-chain identity
# (declare_id). Deleting it mints a new random program id on every deploy.
echo "Building SBF program (from programs/csv-seal)..."
SBF_OUT="$(pwd)/target/deploy"
mkdir -p "$SBF_OUT"
rm -f "$SBF_OUT/csv_seal.so"   # clean the artifact only, keep the keypair
( cd programs/csv-seal && cargo build-sbf --sbf-out-dir "$SBF_OUT" )
# Best-effort IDL for off-chain clients (verifier seeding, tests). Non-fatal.
$ANCHOR build --no-idl >/dev/null 2>&1 || true

# Locate the built .so robustly — build-sbf can emit to any of these.
SO=""
for cand in \
    "target/deploy/csv_seal.so" \
    "programs/csv-seal/target/deploy/csv_seal.so" \
    "programs/csv-seal/target/sbf-solana-solana/release/csv_seal.so" \
    "target/verifiable/csv_seal.so"; do
    if [ -f "$cand" ]; then SO="$cand"; break; fi
done
if [ -z "$SO" ]; then
    echo "ERROR: could not locate a freshly built csv_seal.so."
    echo "Build likely failed. Try: (cd programs/csv-seal && cargo build-sbf)"
    exit 1
fi
SO_SIZE=$(stat -c%s "$SO")
echo "Program artifact: $SO (${SO_SIZE} bytes)"

# Ensure a stable program keypair exists (identity == declare_id).
PROGRAM_KP="target/deploy/csv_seal-keypair.json"
if [ ! -f "$PROGRAM_KP" ]; then
    echo "No program keypair found; generating one (this sets a NEW program id)."
    solana-keygen new --no-bip39-passphrase --silent --outfile "$PROGRAM_KP"
    echo "Run 'anchor keys sync' and rebuild so declare_id matches, then re-run."
fi
echo ""

# --- Deploy --------------------------------------------------------------
# GOTCHA (fixed here): Solana programs can be large; `solana program deploy`
# reserves 2x the .so size for upgrade headroom by default, which can exceed a
# modestly funded wallet's balance. We size programdata to the .so plus an
# explicit, opt-in headroom (CSV_SOLANA_MAXLEN_HEADROOM bytes; default 0 = exact,
# cheapest). NOTE: a later upgrade to a binary LARGER than max-len needs
# `solana program extend <program_id> <bytes>` first.
HEADROOM="${CSV_SOLANA_MAXLEN_HEADROOM:-0}"
MAX_LEN=$(( SO_SIZE + HEADROOM ))
declare -a DEPLOY_KP_ARG=()
if [ -n "$KEYPAIR_ARG" ]; then
    if ! jq empty "$KEYPAIR_FILE" 2>/dev/null; then
        echo "ERROR: Keypair file is not valid JSON: $KEYPAIR_FILE"; exit 1
    fi
    DEPLOY_KP_ARG=(--keypair "$KEYPAIR_FILE")
fi

echo "Deploying to ${NETWORK} (--max-len ${MAX_LEN})..."
solana program deploy "$SO" \
    --program-id "$PROGRAM_KP" \
    --url "$RPC_URL" \
    --max-len "$MAX_LEN" \
    "${DEPLOY_KP_ARG[@]}"
deploy_exit_code=$?

if [ $deploy_exit_code -ne 0 ]; then
    echo "ERROR: solana program deploy failed (exit $deploy_exit_code)."
    echo "  - 'insufficient funds': fund the wallet, or keep CSV_SOLANA_MAXLEN_HEADROOM=0."
    echo "  - upgrading and the new binary is larger than the reserved size:"
    echo "      solana program extend ${program_id:-<program_id>} <extra_bytes> --url $RPC_URL"
    exit 1
fi

# Extract program ID from the keypair file
if [ -n "$KEYPAIR_ARG" ]; then
    program_id=$(solana-keygen pubkey target/deploy/csv_seal-keypair.json --keypair "$KEYPAIR_FILE" --url "$RPC_URL" 2>/dev/null || echo "")
else
    program_id=$(solana-keygen pubkey target/deploy/csv_seal-keypair.json --url "$RPC_URL" 2>/dev/null || echo "")
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

# Initialize the base registry account (Anchor 1.0.2 syntax). NOTE: this does NOT
# enable mint. Under RFC-0012 the thin-registry mint is authorized by a verifier
# set, which is seeded separately (see the fail-closed notice in the summary).
echo "Initializing base registry account..."
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

# Update ~/.csv/config.toml
CONFIG_FILE="$HOME/.csv/config.toml"
if [ -f "$CONFIG_FILE" ]; then
    echo "Updating $CONFIG_FILE..."
    if command -v python3 &>/dev/null; then
        python3 -c "
import sys
try:
    with open('$CONFIG_FILE', 'r') as f:
        content = f.read()
    # Update program_id for solana chain
    import re
    content = re.sub(
        r'program_id = \"[^\"]+\"',
        'program_id = \"$program_id\"',
        content
    )
    with open('$CONFIG_FILE', 'w') as f:
        f.write(content)
    print('Config updated: solana.program_id = $program_id')
except Exception as e:
    print(f'ERROR updating config: {e}', file=sys.stderr)
    sys.exit(1)
"
    else
        echo "WARNING: python3 not found, cannot auto-update config"
        echo "Please manually update $CONFIG_FILE"
        echo "Set chains.solana.program_id = ${program_id}"
    fi
else
    echo "WARNING: $CONFIG_FILE not found, skipping config update"
fi

# Update deployment manifest
echo "Updating deployment manifest..."
MANIFEST_PATH="../../../deployments/deployment-manifest.json"
if [ -f "$MANIFEST_PATH" ]; then
    if command -v python3 &>/dev/null; then
        python3 -c "
import json
import sys
from datetime import datetime, timezone

try:
    with open('$MANIFEST_PATH', 'r') as f:
        manifest = json.load(f)

    # Update solana deployment info
    if 'deployments' in manifest and 'solana' in manifest['deployments']:
        sol = manifest['deployments']['solana']
        sol['network'] = '$NETWORK'
        # program_id is the RFC-0012 §9.2 destinationContract.
        sol['program_id'] = '$program_id'
        sol['verified'] = True
        # A fresh program has an unseeded verifier registry PDA; mint stays
        # fail-closed until initialize_verifier_registry(verifiers, threshold) is
        # run. Reset recorded verifier state so the manifest never advertises stale keys.
        sol['verifier_set'] = []
        sol['mint_threshold'] = 0
        # datetime.UTC needs Python 3.11+; timezone.utc works everywhere.
        manifest['updated_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    with open('$MANIFEST_PATH', 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print('Deployment manifest updated successfully')
except Exception as e:
    print(f'ERROR updating manifest: {e}', file=sys.stderr)
    sys.exit(1)
"
        echo "Manifest updated: solana.program_id = ${program_id}"
    else
        echo "WARNING: python3 not found, cannot auto-update deployment manifest"
        echo "Please manually update $MANIFEST_PATH"
        echo "Set deployments.solana.program_id = ${program_id}"
    fi
else
    echo "WARNING: Deployment manifest not found at $MANIFEST_PATH"
fi

echo ""
echo "IMPORTANT — mint is FAIL-CLOSED until the verifier registry is seeded."
echo "  A freshly deployed program has an empty verifier registry. Seed it with the"
echo "  runtime's secp256k1 compressed 33-byte verifier pubkey using the helper:"
echo ""
echo "    cd $(pwd)"
echo "    npm i @coral-xyz/anchor @solana/web3.js   # one-time"
echo "    node ../scripts/seed-verifier.js init <verifier_pubkey_hex> 1"
echo "    node ../scripts/seed-verifier.js show     # verify"
echo ""
echo "  Then record verifier_set + mint_threshold in deployments/deployment-manifest.json"
echo "  and give the matching private key to the runtime: export CSV_MINT_VERIFIER_KEY=<hex>."
echo "  Full guide: csv-docs/runbooks/MINT_VERIFIER_OPERATIONS.md"
if [ -n "${CSV_MINT_VERIFIER_PUBKEY:-}" ] && command -v node &>/dev/null; then
    echo ""
    echo "CSV_MINT_VERIFIER_PUBKEY is set — attempting to seed the verifier now..."
    if [ -d node_modules/@coral-xyz/anchor ]; then
        node ../scripts/seed-verifier.js init "$CSV_MINT_VERIFIER_PUBKEY" 1 || \
            echo "  seed failed (see above); run it manually."
    else
        echo "  node deps not installed; run 'npm i @coral-xyz/anchor @solana/web3.js' then the helper above."
    fi
fi
echo ""
echo "Next steps:"
echo "1. Update Anchor.toml with the program ID: ${program_id}"
echo "2. Update your csv-cli configuration to use this program ID"
echo ""
echo "Build/deploy notes (fixed in this script):"
echo "  - 'cargo build-sbf' is run from programs/csv-seal/ (nested workspace);"
echo "    from contracts/ it silently produces no .so."
echo "  - Deployed with '--max-len' sized to the .so (+CSV_SOLANA_MAXLEN_HEADROOM)"
echo "    to avoid the default 2x programdata rent on large programs."
