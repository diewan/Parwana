#!/usr/bin/env python3
"""Independent checker for the frozen GitHub deployment accountability slice.

This intentionally does not encode protocol objects. It consumes the released
canonical mandate bytes and independently checks their digest, signature,
intent binding, and replay-journal conclusion.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile


DOMAIN = "csv.accountability.mandate.v1"
DOMAIN_PREFIX = "urn:lnp-bp:csv:"
ID_PREFIX = b"action-mandate-v1\x00"
ALGORITHM = "org.diewan.signature.ed25519.v1"


class Rejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def tagged_hash(name: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256((DOMAIN_PREFIX + name).encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def decode_hex(value: object, field: str, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise Rejected("MalformedStructure")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise Rejected("MalformedStructure") from error
    if size is not None and len(decoded) != size:
        raise Rejected("MalformedStructure")
    return decoded


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    # SubjectPublicKeyInfo prefix for an Ed25519 raw 32-byte public key.
    public_der = bytes.fromhex("302a300506032b6570032100") + public_key
    with tempfile.TemporaryDirectory(prefix="parwana-independent-") as directory:
        public_path = os.path.join(directory, "public.der")
        signature_path = os.path.join(directory, "signature.bin")
        message_path = os.path.join(directory, "message.bin")
        for path, content in (
            (public_path, public_der),
            (signature_path, signature),
            (message_path, message),
        ):
            with open(path, "wb") as output:
                output.write(content)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", public_path, "-rawin", "-in", message_path,
                "-sigfile", signature_path,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if result.returncode != 0:
        raise Rejected("MandateSignatureInvalid")


def check(document: object) -> dict[str, str]:
    if not isinstance(document, dict) or document.get("profile") != "github-deployment-v1":
        raise Rejected("UnsupportedProfile")
    if document.get("algorithm") != ALGORITHM:
        raise Rejected("AlgorithmDisallowed")

    canonical = decode_hex(document.get("mandate_canonical_hex"), "mandate_canonical_hex")
    expected_id = decode_hex(document.get("mandate_id"), "mandate_id", 32)
    actual_id = tagged_hash(DOMAIN, ID_PREFIX + canonical)
    if actual_id != expected_id:
        raise Rejected("CanonicalDigestMismatch")

    intent_id = decode_hex(document.get("intent_id"), "intent_id", 32)
    mandate_intent_id = decode_hex(document.get("mandate_intent_id"), "mandate_intent_id", 32)
    if intent_id != mandate_intent_id:
        raise Rejected("IntentMismatch")

    public_key = decode_hex(document.get("public_key"), "public_key", 32)
    signature = decode_hex(document.get("signature"), "signature", 64)
    verify_signature(public_key, signature, actual_id)

    journal = document.get("consumed_mandate_ids")
    if not isinstance(journal, list) or any(not isinstance(item, str) for item in journal):
        raise Rejected("ReplayStatusUnknown")
    if document["mandate_id"] in journal:
        raise Rejected("ReplayDetected")
    return {"disposition": "valid", "reason": "Valid"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check.py VECTOR.json", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as source:
            result = check(json.load(source))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError):
        reason = "MalformedStructure"
    except Rejected as rejection:
        reason = rejection.reason
    print(json.dumps({"disposition": "invalid", "reason": reason}, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
