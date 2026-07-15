#!/usr/bin/env bash
# Read-only release and package validation for the Rust workspace.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

metadata="$(mktemp)"
trap 'rm -f "$metadata"' EXIT

cargo metadata --locked --format-version 1 >"$metadata"
python3 scripts/check-contract-manifest.py
CXXFLAGS="-include cstdint" cargo test --locked -p csv-architecture \
  --test dep_graph_constitution workspace_release_metadata_is_coherent

while IFS= read -r package; do
  echo "Checking package contents: $package"
  cargo package --locked --allow-dirty --list -p "$package" >/dev/null
done < <(
  jq -r '.packages[]
    | select(.source == null and (.publish == null or (.publish | length > 0)))
    | .name' "$metadata" | sort
)

echo "Release metadata and package contents are valid."
