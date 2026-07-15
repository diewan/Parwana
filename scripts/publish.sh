#!/usr/bin/env bash
# Dry-run-first, dependency-ordered Rust release workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing release from a dirty worktree" >&2
  exit 1
fi

tag="${RELEASE_TAG:-$(git describe --exact-match --tags HEAD 2>/dev/null || true)}"
release_group="${RELEASE_GROUP:-workspace}"
if [[ -z "$tag" ]] || ! git cat-file -e "${tag}^{tag}" 2>/dev/null; then
  echo "an annotated RELEASE_TAG pointing at HEAD is required" >&2
  exit 1
fi

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  echo "cargo-semver-checks is required for a release; install it before retrying" >&2
  exit 1
fi

scripts/check-release.sh
CXXFLAGS="-include cstdint" cargo test --workspace --all-features --locked

metadata="$(mktemp)"
trap 'rm -f "$metadata"' EXIT
cargo metadata --locked --format-version 1 >"$metadata"

# Topo-sort dependency -> dependent edges. Independently publishable crates do
# not appear in an edge, so append them after the ordered graph; they have no
# internal ordering constraint and must still be packaged.
publishable="$(jq -r '.packages[] | select(.source == null and (.publish == null or (.publish | length > 0))) | .name' "$metadata" | sort)"
edges="$(jq -r '
  [.packages[] | select(.source == null and (.publish == null or (.publish | length > 0))) | .name] as $publishable
  | .packages[] | select(.name as $name | $publishable | index($name))
  | .name as $package
  | .dependencies[] | select(.name as $dependency | $publishable | index($dependency))
  | "\(.name) \($package)"' "$metadata")"
ordered="$(printf '%s\n' "$edges" | sed '/^$/d' | tsort)"
mapfile -t packages < <(printf '%s\n%s\n' "$ordered" "$publishable" | awk 'NF && !seen[$0]++')

case "$release_group" in
  workspace) ;;
  core) selected='csv-algebra csv-wire csv-hash csv-protocol csv-verifier' ;;
  runtime) selected='csv-admission csv-chain-ports csv-coordinator csv-storage csv-observability csv-runtime csv-sdk' ;;
  adapters) selected='csv-adapter-factory csv-bitcoin csv-ethereum csv-solana csv-sui csv-aptos csv-celestia' ;;
  tools) selected='csv-cli csv-wallet csv-keys csv-store csv-p2p csv-examples' ;;
  *) echo "unknown RELEASE_GROUP: $release_group" >&2; exit 2 ;;
esac
if [[ "$release_group" != workspace ]]; then
  filtered=()
  for package in "${packages[@]}"; do
    if [[ " $selected " == *" $package "* ]]; then
      filtered+=("$package")
    fi
  done
  packages=("${filtered[@]}")
fi

provenance_dir="target/release-provenance"
mkdir -p "$provenance_dir"
provenance="$provenance_dir/${tag}.txt"
{
  echo "tag=$tag"
  echo "commit=$(git rev-parse HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$provenance"

for package in "${packages[@]}"; do
  echo "Packaging $package"
  cargo semver-checks check-release -p "$package"
  cargo package --locked -p "$package"
  artifact="target/package/${package}-$(cargo metadata --no-deps --format-version 1 | jq -r --arg p "$package" '.packages[] | select(.name == $p) | .version').crate"
  sha256sum "$artifact" >>"$provenance"
done

if [[ "${CSV_RELEASE_PUBLISH:-0}" == "1" ]]; then
  for package in "${packages[@]}"; do
    echo "Publishing $package"
    cargo publish --locked -p "$package"
  done
else
  echo "Dry run complete; provenance: $provenance"
  echo "Set CSV_RELEASE_PUBLISH=1 only after maintainer approval to publish."
fi
