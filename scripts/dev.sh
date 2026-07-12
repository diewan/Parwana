#!/usr/bin/env bash
# Validate the local monorepo dependency graph.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo metadata --locked --format-version 1 >/dev/null
echo "Local versioned path dependencies are ready for development."
