#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# publish.sh — Switch all Cargo.toml dependencies from `path =`
#              back to `git =` for publishing.
#
# Run before publishing any crate to crates.io.
# Run `dev.sh` to switch back to `path =` for local development.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "🔧 Switching path dependencies → git dependencies..."

# Map: crate name → git URL
declare -A GIT_URLS
GIT_URLS["csv-core"]="https://github.com/Diewan/csv-core.git"
GIT_URLS["csv-runtime"]="https://github.com/Diewan/csv-runtime.git"
GIT_URLS["csv-sdk"]="https://github.com/Diewan/csv-sdk.git"
GIT_URLS["csv-keys"]="https://github.com/Diewan/csv-keys.git"
GIT_URLS["csv-store"]="https://github.com/Diewan/csv-store.git"
GIT_URLS["csv-p2p"]="https://github.com/Diewan/csv-p2p.git"
GIT_URLS["csv-observability"]="https://github.com/Diewan/csv-observability.git"
GIT_URLS["csv-bitcoin"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-ethereum"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-solana"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-sui"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-aptos"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-celestia"]="https://github.com/Diewan/csv-adapters.git"
GIT_URLS["csv-explorer-shared"]="https://github.com/Diewan/csv-explorer.git"
GIT_URLS["csv-explorer-storage"]="https://github.com/Diewan/csv-explorer.git"

# Find all Cargo.toml files
CARGO_FILES=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/contracts/*' 2>/dev/null)

for file in $CARGO_FILES; do
    needs_change=false
    for crate_name in "${!GIT_URLS[@]}"; do
        git_url="${GIT_URLS[$crate_name]}"
        # Check if this file has a path dependency for this crate
        if grep -q "${crate_name} = { path *= *\"" "$file" 2>/dev/null; then
            # Extract the version if present, otherwise use 0.1.0
            version="0.1.0"
            # If there's an existing version field in the old path dep, keep it
            if grep -q "${crate_name} = { path = \"[^\"]*\", version = \"[^\"]*\"" "$file" 2>/dev/null; then
                version=$(grep "${crate_name} = { path = \"[^\"]*\", version = \"[^\"]*\"" "$file" | sed 's/.*version = "\([^"]*\)".*/\1/')
            fi
            # Replace path dependency with git dependency
            sed -i "s|${crate_name} = { path = \"[^\"]*\"\(.*\)}|${crate_name} = { version = \"${version}\", git = \"${git_url}\"\1}|" "$file"
            # Handle case where path dep already has extra fields like optional
            sed -i "s|${crate_name} = { path = \"[^\"]*\", |${crate_name} = { version = \"${version}\", git = \"${git_url}\", |" "$file"
            needs_change=true
        fi
    done
    if [ "$needs_change" = true ]; then
        echo "  ✓ $file"
    fi
done

# Make sure workspace Cargo.toml doesn't have patch sections (they were for the alternative approach)
if grep -q '\[patch' "$ROOT/Cargo.toml" 2>/dev/null; then
    echo "  ⚠️  Workspace Cargo.toml still has [patch] sections — removing them for publish"
    # Strip [patch] sections from workspace Cargo.toml
    sed -i '/^\[patch\..*/,/^\[/ { /^\[patch\..*/d; /^\[.*\]/!d; }' "$ROOT/Cargo.toml"
fi

echo "✅ All dependencies switched to git dependencies."
echo "   Each crate can now be published independently."