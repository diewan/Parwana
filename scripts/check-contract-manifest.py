#!/usr/bin/env python3
"""Fail closed when Parwana's contract manifest or consumer pins drift."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tomllib
from datetime import date
from pathlib import Path


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_REFS = {"latest", "main", "master", "develop", "development", "head"}
COMPATIBILITY_KEYS = ("wire", "semantic", "source_api", "stored_data", "policy")


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def corpus_digest(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise ValueError("conformance corpus is empty")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def validate_source(source: dict, stability: str, label: str) -> list[str]:
    failures: list[str] = []
    kind = source.get("kind")
    value = source.get("value", "")
    if not isinstance(value, str) or value.lower() in FORBIDDEN_REFS:
        return [f"{label}: source reference is floating or missing"]
    if stability == "stable":
        if kind != "release_tag" or not SEMVER_TAG.fullmatch(value):
            failures.append(f"{label}: stable contracts require an immutable SemVer release tag")
    elif stability == "pre_stable":
        if kind != "commit" or not SHA40.fullmatch(value):
            failures.append(f"{label}: pre-stable contracts require an exact 40-character commit SHA")
    else:
        failures.append(f"{label}: unsupported stability `{stability}`")
    return failures


def validate_manifest(repo_root: Path, manifest: dict) -> list[str]:
    failures: list[str] = []
    if manifest.get("schema_version") != 1:
        failures.append("manifest: unsupported schema_version")
    if manifest.get("publisher") != "github.com/diewan/parwana":
        failures.append("manifest: Parwana must be the sole publisher")
    stability = manifest.get("stability", "")
    failures.extend(validate_source(manifest.get("source", {}), stability, "manifest"))
    corpus = manifest.get("corpus", {})
    if corpus.get("algorithm") != "sha256-length-prefixed-tree-v1":
        failures.append("manifest: unsupported corpus digest algorithm")
    declared_digest = corpus.get("digest", "")
    if not isinstance(declared_digest, str) or not HEX64.fullmatch(declared_digest):
        failures.append("manifest: corpus digest must be 64 lowercase hexadecimal characters")
    corpus_path = corpus.get("path", "")
    try:
        actual_digest = corpus_digest(repo_root / corpus_path)
        if actual_digest != declared_digest:
            failures.append(
                f"manifest: corpus digest mismatch (declared {declared_digest}, actual {actual_digest})"
            )
    except (OSError, ValueError, TypeError) as error:
        failures.append(f"manifest: cannot digest corpus: {error}")
    compatibility = manifest.get("compatibility", {})
    for key in COMPATIBILITY_KEYS:
        if not compatibility.get(key):
            failures.append(f"manifest: missing compatibility dimension `{key}`")
    return failures


def validate_pin(path: Path, pin: dict, manifest: dict, today: date) -> list[str]:
    label = path.as_posix()
    failures: list[str] = []
    for key in ("consumer", "publisher", "contract_version", "protocol_version", "expires_on"):
        if not pin.get(key):
            failures.append(f"{label}: missing `{key}`")
    if pin.get("publisher") != manifest.get("publisher"):
        failures.append(f"{label}: publisher does not match Parwana manifest")
    if pin.get("contract_version") != manifest.get("contract_version"):
        failures.append(f"{label}: incompatible contract version")
    if pin.get("protocol_version") != manifest.get("protocol_version"):
        failures.append(f"{label}: incompatible protocol version")
    if pin.get("corpus_digest") != manifest.get("corpus", {}).get("digest"):
        failures.append(f"{label}: conformance corpus digest mismatch")
    stability = manifest.get("stability", "")
    failures.extend(validate_source(pin.get("source", {}), stability, label))
    if pin.get("source") != manifest.get("source"):
        failures.append(f"{label}: source pin does not exactly match the publisher manifest")
    try:
        expiry = date.fromisoformat(pin.get("expires_on", ""))
        if expiry < today:
            failures.append(f"{label}: pin expired on {expiry.isoformat()}")
    except (TypeError, ValueError):
        failures.append(f"{label}: expires_on must be an ISO date")
    if pin.get("compatibility") != manifest.get("compatibility"):
        failures.append(f"{label}: compatibility policy is missing or incompatible")
    return failures


def check(repo_root: Path, pins_dir: Path | None, today: date) -> list[str]:
    manifest_path = repo_root / "conformance/contract-manifest.toml"
    try:
        manifest = load_toml(manifest_path)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"manifest: cannot load {manifest_path}: {error}"]
    failures = validate_manifest(repo_root, manifest)
    if pins_dir is None:
        return failures
    expected = {"piteka", "tuppira", "hemion"}
    found: set[str] = set()
    for path in sorted(pins_dir.glob("*.toml")):
        try:
            pin = load_toml(path)
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{path}: cannot load pin: {error}")
            continue
        consumer = pin.get("consumer")
        if isinstance(consumer, str):
            if consumer in found:
                failures.append(f"{path}: duplicate consumer `{consumer}`")
            found.add(consumer)
        failures.extend(validate_pin(path, pin, manifest, today))
    for missing in sorted(expected - found):
        failures.append(f"pins: missing required consumer `{missing}`")
    for unknown in sorted(found - expected):
        failures.append(f"pins: unknown consumer `{unknown}`")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--pins-dir", type=Path)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    if args.pins_dir and args.pin_file:
        parser.error("--pins-dir and --pin-file are mutually exclusive")
    repo_root = args.repo_root.resolve()
    if args.pin_file:
        manifest_path = repo_root / "conformance/contract-manifest.toml"
        try:
            manifest = load_toml(manifest_path)
            pin = load_toml(args.pin_file.resolve())
            failures = validate_manifest(repo_root, manifest)
            failures.extend(validate_pin(args.pin_file.resolve(), pin, manifest, args.today))
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures = [f"contract pin cannot be loaded: {error}"]
    else:
        failures = check(repo_root, args.pins_dir.resolve() if args.pins_dir else None, args.today)
    if failures:
        print("contract manifest violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Parwana contract manifest and consumer pins: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
