#!/usr/bin/env bash
# Enforce reviewed public API snapshots for protected L0-L4 crates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
readonly crates=(csv-algebra csv-wire csv-hash csv-protocol csv-verifier)
readonly snapshot_dir="csv-architecture/api-snapshots"

if ! cargo public-api --version >/dev/null 2>&1; then
  echo "cargo-public-api is required; install cargo-public-api before running this gate" >&2
  exit 1
fi

mkdir -p "$snapshot_dir"
for crate in "${crates[@]}"; do
  snapshot="$snapshot_dir/${crate}.txt"
  current="$(mktemp)"
  cargo public-api -p "$crate" >"$current"
  if [[ "${CORE_API_SNAPSHOT_UPDATE:-0}" == "1" ]]; then
    mv "$current" "$snapshot"
    echo "updated $snapshot"
  elif [[ ! -f "$snapshot" ]]; then
    rm -f "$current"
    echo "missing $snapshot; regenerate intentionally with CORE_API_SNAPSHOT_UPDATE=1" >&2
    exit 1
  else
    if ! diff --unified=3 "$snapshot" "$current"; then
      rm -f "$current"
      exit 1
    fi
    rm -f "$current"
  fi
done
