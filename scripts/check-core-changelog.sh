#!/usr/bin/env bash
# Require an explicit core changelog entry whenever L0-L4 source or manifest changes.
set -euo pipefail
base="${1:-HEAD^}"
changed="$({ git diff --name-only "$base"...HEAD; git diff --name-only; git ls-files --others --exclude-standard; } | sort -u)"
if printf '%s\n' "$changed" | grep -Eq '^(csv-algebra|csv-wire|csv-hash|csv-protocol|csv-verifier)/(src|Cargo.toml)'; then
  if ! printf '%s\n' "$changed" | grep -qx 'csv-docs/CHANGELOG_CORE.md'; then
    echo "protected L0-L4 change requires csv-docs/CHANGELOG_CORE.md update" >&2
    exit 1
  fi
fi
