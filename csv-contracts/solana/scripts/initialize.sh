#!/usr/bin/env bash
# Initialize the LockRegistry for the CSV Seal program
# This script is called by Anchor via `anchor run initialize`
# Usage: ./initialize.sh [network]

set -euo pipefail

NETWORK="${1:-devnet}"

cd "$(dirname "$0")/contracts"

echo "Initializing LockRegistry on ${NETWORK}..."

# The actual initialization should be done via the tests or manually
# This is a placeholder since the deploy script handles initialization gracefully
echo "Note: LockRegistry initialization should be done via anchor test or manually"
echo "Run: anchor test --skip-local-validator --provider.cluster ${NETWORK}"
exit 0
