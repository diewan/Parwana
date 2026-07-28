#!/usr/bin/env python3
"""Validate the first Parwana V2 release declaration and its content pins."""

from hashlib import sha256
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "conformance/parwana-v2-release.toml"


def digest(relative_path: str) -> str:
    return sha256((ROOT / relative_path).read_bytes()).hexdigest()


release = tomllib.loads(RELEASE.read_text(encoding="utf-8"))
assert release["release_status"] == "first_public_release"
assert release["compatibility"]["prior_public_release"] == "none"
assert release["compatibility"]["v1_auto_upgrade"] is False
assert release["compatibility"]["v1_portable_non_equivocation"] == "unavailable"

for package in ("portable_conformance", "transition_vectors", "closure_support_matrix"):
    declared = release[package]
    assert digest(declared["path"]) == declared["sha256"], (
        f"{package} digest does not match {declared['path']}"
    )

matrix = tomllib.loads(RELEASE.read_text(encoding="utf-8"))
adapters = {
    (adapter["chain_id"], adapter["network_id"], adapter["proof_kind"])
    for adapter in matrix["closure_adapters"]
    if adapter["claim_c"]
}
expected = {
    ("bitcoin", "signet", "bitcoin-spv-v1"),
    ("ethereum", "sepolia", "ethereum-nullifier-storage-v1"),
    ("sui", "testnet", "sui-object-consumption-v1"),
    ("aptos", "testnet", "aptos-resource-nullifier-v1"),
    ("solana", "devnet", "solana-account-nullifier-v1"),
}
assert adapters == expected, "release metadata advertises an unsupported closure adapter"

print("Parwana V2 first-release metadata and content pins are valid.")
