#!/usr/bin/env python3
"""Validate the first Parwana V2 release declaration and its content pins."""

import json
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

for package in (
    "portable_conformance",
    "reason_code_registry",
    "transition_vectors",
    "closure_support_matrix",
):
    declared = release[package]
    assert digest(declared["path"]) == declared["sha256"], (
        f"{package} digest does not match {declared['path']}"
    )

# Every reason code the portable package tells a consumer to expect must be a
# member of the registry this release pins. The Rust gates check the same thing
# from inside the workspace; this checks it from the published files alone,
# which is the view a consumer has.
manifest = json.loads((ROOT / release["portable_conformance"]["path"]).read_text(encoding="utf-8"))
registry = (ROOT / release["reason_code_registry"]["path"]).read_text(encoding="utf-8")
assert manifest["reason_code_registry"]["path"] == release["reason_code_registry"]["path"], (
    "the portable package names a different registry than the release pins"
)
for case in manifest["cases"]:
    code = case["expected_reason_code"]
    assert f'"{code}"' in registry, (
        f"case {case['id']} declares {code}, which the pinned registry does not publish"
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
