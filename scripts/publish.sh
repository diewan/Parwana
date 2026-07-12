#!/usr/bin/env bash
# Run non-mutating release checks. Publishing remains an explicit operator step.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/check-release.sh"

cat <<'EOF'
Release checks passed. Publish crates in dependency order with:
  cargo publish --locked -p <crate>

Cargo strips each local `path` and retains its `version` when preparing the
registry manifest; no manifest rewriting is required.
EOF
