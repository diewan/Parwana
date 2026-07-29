#!/usr/bin/env bash
# Read-only release and package validation for the Rust workspace.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

metadata="$(mktemp)"
trap 'rm -f "$metadata"' EXIT

cargo metadata --locked --format-version 1 >"$metadata"
python3 scripts/check-contract-manifest.py
python3 scripts/check-v2-release.py
cargo run --locked -q -p csv-sdk --example generate_portable_conformance -- --check
CXXFLAGS="-include cstdint" cargo test --locked \
  -p csv-runtime isolated_recipients_cannot_both_accept_one_source
CXXFLAGS="-include cstdint" cargo test --locked \
  -p csv-runtime send_resume
CXXFLAGS="-include cstdint" cargo test --locked \
  -p csv-storage orphaning_checkpoint
CXXFLAGS="-include cstdint" cargo test --locked \
  -p csv-testkit --test conformance_corpus
CXXFLAGS="-include cstdint" cargo test --locked \
  -p csv-sdk --test v2_consumer_facade
CXXFLAGS="-include cstdint" cargo test --locked -p csv-architecture \
  --test dep_graph_constitution workspace_release_metadata_is_coherent

while IFS= read -r package; do
  echo "Checking package contents: $package"
  cargo package --locked --allow-dirty --list -p "$package" >/dev/null
done < <(
  jq -r '.workspace_members as $members
    | .packages[]
    | select(
        (.id as $id | $members | index($id))
        and (.publish == null or (.publish | length > 0))
      )
    | .name' "$metadata" | sort
)

echo "Release metadata and package contents are valid."
