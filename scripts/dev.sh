#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# dev.sh — Switch all Cargo.toml dependencies from `git =` to
#          `path =` for local workspace development.
#
# Run this after cloning all repos to build/test locally.
# Run `publish.sh` to switch back to `git =` before publishing.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "🔧 Switching git dependencies → path dependencies..."

# List of repos we manage
declare -A LOCAL_PATHS
LOCAL_PATHS["csv-core"]="csv-core"
LOCAL_PATHS["csv-runtime"]="csv-runtime"
LOCAL_PATHS["csv-sdk"]="csv-sdk"
LOCAL_PATHS["csv-keys"]="csv-keys"
LOCAL_PATHS["csv-store"]="csv-store"
LOCAL_PATHS["csv-p2p"]="csv-p2p"
LOCAL_PATHS["csv-observability"]="csv-observability"
LOCAL_PATHS["csv-bitcoin"]="csv-adapters/csv-bitcoin"
LOCAL_PATHS["csv-ethereum"]="csv-adapters/csv-ethereum"
LOCAL_PATHS["csv-solana"]="csv-adapters/csv-solana"
LOCAL_PATHS["csv-sui"]="csv-adapters/csv-sui"
LOCAL_PATHS["csv-aptos"]="csv-adapters/csv-aptos"
LOCAL_PATHS["csv-celestia"]="csv-adapters/csv-celestia"
LOCAL_PATHS["csv-explorer-shared"]="csv-explorer/shared"
LOCAL_PATHS["csv-explorer-storage"]="csv-explorer/storage"

# Find all Cargo.toml files
CARGO_FILES=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/contracts/*' 2>/dev/null)

for file in $CARGO_FILES; do
    needs_change=false
    for crate_name in "${!LOCAL_PATHS[@]}"; do
        local_path="${LOCAL_PATHS[$crate_name]}"
        # Check if this file has a git dependency for this crate
        if grep -q "${crate_name}.*git.*github.com" "$file" 2>/dev/null; then
            # Replace: crate = { git = "https://...", ... } or crate = { version = "x", git = "..." }
            sed -i "s|${crate_name} = { version = \"[^\"]*\", git  *= *\"https://[^\"]*\"\(.*\)}|${crate_name} = { path = \"${local_path}\"\1}|" "$file"
            sed -i "s|${crate_name} = { git  *= *\"https://[^\"]*\"\(.*\)}|${crate_name} = { path = \"${local_path}\"\1}|" "$file"
            needs_change=true
        fi
    done
    if [ "$needs_change" = true ]; then
        echo "  ✓ $file"
    fi
done

echo "✅ All dependencies switched to path dependencies."
echo "   Run 'cargo build --workspace' to verify."